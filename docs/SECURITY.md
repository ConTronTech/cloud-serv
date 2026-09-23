# cloud-serv — Security & Encryption Verification

This documents the end-to-end encryption design, **who it protects against**, what has been
**verified** (with the tests that prove it), and the **residual risks** that are known and
accepted (or queued). It is deliberately honest about limits — "it's encrypted" is not a
security property; *encrypted against a specific adversary* is.

## Threat model

The design assumes the **server is untrusted** — a compromised host, a malicious operator, a
stolen disk, or an attacker who has fully owned the box. Zero-knowledge means such an
adversary learns neither file **contents** nor **names**.

- **In scope:** confidentiality of file contents and names against the server/disk;
  integrity of file contents against server-side tampering (reorder / truncate / splice);
  password never reaching the server; data key never reaching the server.
- **Out of scope:** a compromised *client* (malicious browser, XSS in the page, keylogger);
  traffic analysis / metadata that is structurally visible (see Residual risks); denial of
  service; availability.

## Key hierarchy

```
password ──PBKDF2-HMAC-SHA256(310k, per-user 16-byte salt)──▶ 512 bits
                                                             ├─ [0:32]  AUTH key  → sent to server (server stores PBKDF2-HMAC-SHA256(AUTH key, 200000 iterations))
                                                             └─ [32:64] KEK       → stays in the browser, never sent
DEK  = random 256-bit data key
        ├─ wrapped by KEK              (unlock with password)
        └─ wrapped by a random recovery key (unlock without password; shown once, downloadable)
per-file content key = random 256-bit, wrapped by the DEK
file/folder name     = encrypted under the DEK
```

- The server only ever receives the **AUTH key** (at login) and **wrapped** blobs it cannot
  open. It never sees the password, the KEK, the DEK, content keys, contents, or names.
- Forgotten password **and** lost recovery key ⇒ permanent, unrecoverable data loss. This is
  the cost of zero-knowledge, not a defect.

## Content encryption (STREAM-style AEAD)

Contents are AES-256-GCM in 1 MB plaintext frames. Each frame on disk is
`[nonce(12) ‖ ciphertext ‖ tag(16)]` with a fresh random 96-bit nonce, under a per-file
random key. **The frame index and a final-frame flag are bound into the GCM additional
authenticated data (AAD)**, giving whole-file integrity: an untrusted server cannot reorder,
drop (truncate), duplicate, or splice frames without the tag check failing on decrypt.
Names are encrypted with AES-256-GCM under the DEK (`iv.ct` base64).

## What has been verified (`tests/`, run with `bash tests/run.sh`)

Unit (`crypto.test.js`, Node WebCrypto) and a real-API end-to-end test
(`test_e2e.sh` + `e2e.node.js`) together assert:

- Correct password derives the same AUTH key and unwraps the DEK; **wrong password cannot**
  unwrap the DEK; the recovery key independently unwraps the DEK.
- Content round-trips at 0 / 1 / 100 / 1 MB / 1 MB+1 / multi-MB sizes.
- **Tampering is rejected:** wrong key, flipped ciphertext byte, **reordered frames**,
  **truncated file**, and **duplicated/appended frame** all fail the GCM tag check.
- Driving the real HTTP API like the browser: contents on disk are the ciphertext with **no
  plaintext anywhere on disk**, and **no plaintext filename/folder-name in the database file
  (including the WAL)**; the server stores a blank plaintext name; `wrappedKey`/`encName`
  round-trip and decrypt back to the originals.
- Server logs do not record file names or bodies (checked); the legacy plaintext upload path
  is preserved only for non-E2E clients/tests.

Current suite: **112 assertions, 0 failures**, also run in CI on every push/PR.

## Residual risks (known)

1. **File substitution by a malicious server.** The server maps `file id → (blob, wrapped
   key, enc name)`. Since it cannot forge a wrapped key (no DEK), it can only *shuffle your
   own* existing (blob, key, name) triples — e.g. serve file B's content+key+name under file
   A's id. Frame-level integrity does not catch this because B is a validly-authenticated
   object. *Mitigation (queued):* bind a client-chosen file UUID into both the content AAD
   and the encrypted metadata, and verify they match on download.
2. **Offline password attack by a malicious server.** A hostile server can capture the AUTH
   key at login (or use the stored PBKDF2 hash of the AUTH key) and mount an offline dictionary attack
   against the password at PBKDF2 cost per guess. This is inherent to password-derived-key
   E2E. Mitigations: use a strong password; the **recovery key is random 256-bit and immune**
   to this. *Hardening (queued):* raise PBKDF2 iterations toward the OWASP 600k guidance
   (Argon2id isn't in WebCrypto).
3. **Metadata visible to the server:** exact file **sizes**, encrypted-**name lengths**, **folder structure**,
   timestamps, and item counts. Contents, names and mime type are not (mime was encrypted in
   E2E Phase 3.5). Padding sizes/names is a possible future tightening.
4. **DEK lives in `sessionStorage`** (per-tab) for reload UX. Any successful XSS in the page
   could exfiltrate it. Mitigated by a strict CSP (`script-src 'self'`) and a
   `textContent`-only / no-`innerHTML` rendering discipline, but it remains the sharpest
   client-side edge.

## Before exposure (Tailscale)

- Set `RATE_LIMIT_ENABLED=true` in `config.env` (currently `false` for testing).
- **TLS is terminated in the daemon, over Tailscale — no reverse proxy.** `TLS_ENABLED`
  (default `true`), `TLS_CERT_PATH` (default `data/tls/server.crt`), `TLS_KEY_PATH` (default
  `data/tls/server.key`). The self-signed EC P-256 cert (10 years, OpenSSL C API,
  `src/security/tls.cpp`) is regenerated at startup if missing or if its SAN doesn't cover the
  Tailscale IP (`tailscale ip -4`, else an interface in 100.64.0.0/10).
  `scripts/setup-tailscale.sh` installs/brings up Tailscale. `TLS_ENABLED=false` serves plain
  HTTP for local dev and tests. The transport only protects the AUTH key in transit — the
  zero-knowledge guarantees do **not** depend on transport security.
- **Storage permissions:** per-user blob dirs and the DB dir are `0700`, blob files `0600`, TLS
  key `0600` in a `0700` directory. Known small gap: the base `STORAGE_DIR` root itself is not
  chmod `0700`; it is protected only when it sits under the `0700` data directory.
- **Login/session hardening:** rate limiter walks `X-Forwarded-For` right-to-left with IP
  validation; per-email login throttle (5 free failures, then 30s doubling to a 15 min cap,
  429 + `Retry-After`, also for unknown emails); session cookie is always `Secure` and
  HttpOnly (the web client stores/sends no token); API-key create/list/revoke require a login
  session (an `X-API-Key` request is rejected).
- **Known trade-off (M6):** the throttle is keyed by email only, so anyone can lock a known
  email out of logging in for up to 15 minutes. Possible follow-up: key on email+IP, or a higher
  threshold for the email-only bucket.
- **Open (M7):** `/register` still distinguishes already-registered emails (the current
  success-shaped decoy — user id 0, no `Set-Cookie` — is distinguishable and is *not* a fix).
  Decide between (a) generic 409 + tight registration rate limit, risk accepted, or (b) closing
  open registration (admin-created / invite-only accounts).
- **Open design decision (certificate):** browsers require a trusted cert for service workers
  and PWA install. A self-signed cert that was clicked through generally will not let the
  service worker register, and Android needs it trusted to install the PWA. The better option is
  a real cert from `tailscale cert` for the machine's `.ts.net` name.
