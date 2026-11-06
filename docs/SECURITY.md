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

Current suite: **766 checks, 0 failures** (`bash tests/run.sh`), also run in CI on every push/PR.

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

- Rate limiting is on by default (`RATE_LIMIT_ENABLED=true`); only the test harness turns it off.
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
- **M7 (fixed):** self-registration is gated by a shared invite code. `REGISTRATION_INVITE_CODE`
  in `config.env` (empty = registration disabled entirely, the shipped default) and
  `POST /api/auth/register` must carry `inviteCode`. A wrong code, an already-registered email, a
  missing code, and registration-disabled all return the identical
  `403 {"error":"registration is not open"}` (constant-time code compare; the password hash is
  computed on every path), so responses can't enumerate emails. Residual, accepted: someone who
  holds the invite code can still learn whether an email is taken. The first (admin) account does
  not need the code: create it with `./cloud_serv admin create-admin` (see `ADMIN_API.md`), so
  registration can stay closed from the start.
- **Certificate (Tailscale-issued, self-signed fallback):** `TLS_PREFER_TAILSCALE_CERT` (default
  `true`). At startup the daemon first tries a real, browser-trusted cert via the Tailscale CLI
  (`tailscale status --json` for the MagicDNS name, then `tailscale cert --cert-file/--key-file`;
  hostname validated to `[a-z0-9.-]`, every argument shell-quoted). This is what lets service
  workers and Android PWA install work without a warning. If Tailscale is missing, logged out,
  MagicDNS is off, or the command fails, it falls back to the self-signed generator — and that
  fallback still has the trust caveat (clicked-through self-signed certs generally block service
  workers; Android needs trust to install the PWA). An existing cert is preserved (not
  overwritten) when it parses, is not within 24h of expiry, and either covers the Tailscale IP or
  is not self-signed, so a transient tailscaled failure can't destroy a good cert; a self-signed
  cert missing the Tailscale IP is still regenerated.
- **Open (certificate minor points):** `tailscale cert` runs on every start when preferred (a
  boot-time network call; Tailscale caches, so normally quick); the invocation goes through
  `popen`/a shell (mitigated by strict hostname validation + quoting) rather than fork/exec; the
  real path was only tested with a fake `tailscale` on PATH, so smoke-test it once on the real
  box after `scripts/setup-tailscale.sh`.

## Added since September 2026
- **Single sign-on (OIDC, authentik):** authorization code + PKCE S256, `state` + `nonce`,
  `client_secret_basic`. The ID token comes straight from the token endpoint over verified TLS;
  `iss`, `aud`, `exp` and `nonce` are checked. New accounts only for members of
  `OIDC_ALLOWED_GROUP`. **Never matched by email** (that would let any IdP email claim an
  account); existing accounts link explicitly from Settings.
- **Trusted devices:** a non-extractable ECDH P-256 key per browser (IndexedDB). Approval wraps
  the DEK to it (ephemeral ECDH, HKDF-SHA256, AES-GCM, AAD `cloud-serv-device-v1`). The approving
  user compares a 6-digit code (from SHA-256 of the public key) on both screens, so a device
  registered by someone else can't slip through. Revocable; capped per account.
- **Sign-up:** one-time invite codes (stored hashed, single use, optional expiry, race-safe: 15
  parallel uses of one code create exactly one account) and admin-approved sign-up requests
  (max 25 waiting). Same generic answer for every refusal (no account enumeration).
- **Live updates:** `/api/events` WebSocket, session-only (no API keys), same-origin only, 10
  per account / 200 total. It carries only "this list changed" signals, never data.
- **Storage quota is enforced on real bytes:** `stored_size` (bytes on disk) instead of the
  client-reported size; unfinished chunked uploads count; per-account lock around
  check-then-write; idle uploads expire after 24 h.
- **HSTS** (`max-age=31536000`) on every response.
- **systemd sandbox** for service installs (`deploy.sh`): own user, read-only system, write
  access to the data dir only, no capabilities, syscall filter, `MemoryDenyWriteExecute`.
  `systemd-analyze security` exposure **1.4 (OK)**.
- **Companion CLI (`cloud`):** API keys only (no account powers), config `0600`, self-signed
  server certificates are pinned after the user checks the fingerprint, and a changed
  certificate is refused.

## Security sweeps
| Date | What ran | Result |
|---|---|---|
| 2026-09-23 | full manual review ([archive/SECURITY_SWEEP_2026-09-23.md](archive/SECURITY_SWEEP_2026-09-23.md)) | H1, M6-M10, L20 fixed (M6 accepted as a trade-off, see above) |
| 2026-11-05 | AddressSanitizer + UBSan build running the whole suite | 1 bug: uninitialised fields in vendored Crow's request parser, **fixed** (`libs/crow/http_request.h`) |
| 2026-11-05 | endpoint fuzzer: all 70 routes x no-auth/user/admin, hostile IDs, wrong-typed JSON, junk bodies and headers, raw protocol garbage (~6,600 requests, 2 seeds) on the sanitizer build | 0 server errors, 0 crashes, 0 sanitizer reports |
| 2026-11-05 | concurrency: 20 parallel uploads into a full quota, duplicate chunks, one invite used 15x at once, double approvals | **quota bypass found and fixed** (chunked uploads with no declared size; client-reported size used for usage). All races now hold. Covered by `tests/test_quota_race.sh`. |
| 2026-11-05 | code review of OIDC, devices, invites, storage, events, profile | WebSocket state leaked on error and one account could take every live-update slot: **both fixed** |
| 2026-11-05 | probes: cookie flags, CSRF, security headers, folder cycles, cross-user moves, suspended sessions, login timing, disguised images, 60 MB JSON | all held. HSTS was missing: **added**. |
| 2026-11-05 | `scripts/security-audit.sh` | 19/19 (script updated for invite-only sign-up) |

Known open items (accepted for now): API keys survive a password change (separate credentials,
revoked individually, as on GitHub); the DEK in `sessionStorage` (residual risk 4 above).
