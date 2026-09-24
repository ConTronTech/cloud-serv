# cloud-serv — Roadmap

A self-hosted, zero-knowledge personal cloud (files now; notes live; contacts/calendar
later) for web + Android + Linux, run on the user's own PC and later reached over Tailscale.
Backend is C++/Crow + SQLite; the web client is a dependency-free vanilla-JS PWA served
same-origin.

**Zero-knowledge means:** the server never sees the password, the data key, file contents,
or filenames. Forgotten password **and** lost recovery key = permanent data loss — this is
inherent to the design, not a bug.

---

## Done

- **Backend + auth** — multi-user (users / per-user API keys / sessions), all scoped by
  `user_id`. Passwords PBKDF2-HMAC-SHA256; sessions & API keys stored only as SHA-256.
- **Web PWA** — login/register, Drive-style responsive file manager (sidebar/drawer, grid &
  list views, breadcrumbs, action sheets, move picker, multi-select, starred/recent,
  categories), installable (manifest + service worker). XSS-safe (textContent only).
- **Files & media** — per-user folder tree; chunked resumable upload; HTTP Range / 206
  playback; inline preview; nested-folder upload; upload progress bar.
- **Notes** — CRUD + UI.
- **E2E Phase 1 — key management** — PBKDF2(310k) → auth key (to server) + KEK (local);
  random DEK wrapped by the KEK and by a downloadable recovery key. Server stores only
  wrapped key material.
- **E2E Phase 2 — file contents** — chunked AES-256-GCM (1 MB frames), per-file key wrapped
  by the DEK. Encrypt on upload, decrypt on download/preview/thumbnail. Ciphertext on disk.
- **E2E Phase 2b — filenames** — file & folder names encrypted under the DEK; the server
  stores only opaque blobs and browses by structure alone.
- **Tests + CI** — 109 assertions (unit crypto, curl integration, and a real-API
  zero-knowledge end-to-end test proving no plaintext contents on disk and no plaintext name
  in the database). GitHub Actions builds + runs on push/PR.

**What the server can still see today:** file **mime type**, sizes, timestamps, and the
folder structure (which folder holds which items). Names and contents are opaque.

---

## Next

### Phase 3 — client-side search / sort / categories  *(needed, not just nice-to-have)*
Because names are now opaque, the server can no longer search or sort by name for E2E items.
Move these to the client:
- Maintain an in-memory index of decrypted names (already produced by `hydrateNames`).
- Client-side name search across the loaded tree (and/or fetch-all-then-filter).
- Client-side sort by name (server keeps size/date sort).
- Categories: derive from mime client-side (or from encrypted mime once Phase 3.5 lands).

### Phase 3.5 — encrypt mime *(optional, small)*
Fold `mime` into the encrypted metadata so file **type** stops leaking. Costs the
server-side category filter, so it should land with (or after) Phase 3's client categories.

### Phase 4 — streamed decrypt for large video
Today big files download fully before playing (download-then-play). Add MediaSource-based
streaming: fetch + decrypt frame-by-frame and feed the player, so multi-GB video seeks
without buffering the whole file into memory.

### Recovery-key login path
Wrap/unwrap is verified, but the "forgot password → unlock with recovery key → re-wrap DEK
under a new password" flow isn't wired into the UI yet.

---

## Before exposure (Tailscale)

- **Flip `RATE_LIMIT_ENABLED` back to `true`** in `config.env` — it's currently `false` for
  testing (limits are already tuned generous for bulk uploads).
- ~~Reverse proxy / TLS in front~~ — **done differently:** the daemon terminates its own HTTPS
  (self-signed EC P-256, auto-regenerated when the SAN misses the Tailscale IP; `TLS_ENABLED`,
  `TLS_CERT_PATH`, `TLS_KEY_PATH`; `scripts/setup-tailscale.sh`). No reverse proxy.
- **`RATE_LIMIT_ENABLED` is still `false` in `config.env`** — flip it before exposing.
- **Done:** `TLS_PREFER_TAILSCALE_CERT` (default `true`) first tries a real, browser-trusted
  cert via `tailscale cert` for the MagicDNS name (service workers / Android PWA install work
  without a warning); self-signed remains the fallback and that fallback still has the trust
  caveat. **Open:** smoke-test the real Tailscale path once on the real box after
  `scripts/setup-tailscale.sh` (only tested with a fake `tailscale` so far); it runs on every
  start and uses `popen` (validated + quoted).
- **Done:** M7 fixed — registration requires `REGISTRATION_INVITE_CODE` / `inviteCode`
  (empty = disabled, the default; set it only to invite other people). The first admin is
  created with `./cloud_serv admin create-admin`, not by registering. Uniform `403` on every
  failure path. See the sweep's Remediation status.

---

## Deferred

- Content-addressed storage (SHA-256-named, sharded, refcounted dedup) — dropped in favor of
  E2E (per-file random keys defeat dedup by design).
- Server-side thumbnail generation (thumbnails currently decrypt the full image client-side).
- Contacts / calendar apps.
- Android client.
