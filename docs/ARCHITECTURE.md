# Architecture

One C++ program (`cloud_serv`, ~7,200 lines over 28 files) serves the HTTPS API, the live-update socket and the web app. One dependency-free JavaScript web app (~4,100 lines with the HTML and CSS) is the client. Data lives in SQLite plus a folder of blobs.

```
 Browser / installed PWA ─┐                               ┌─ SQLite (cloud.db): accounts, sessions, keys,
 cloud CLI (API key) ─────┼─ HTTPS + WebSocket ─► cloud_serv ─┤   folders, file records, notes, invites, devices...
 curl / scripts ──────────┘    (LAN or Tailscale)   (Crow, C++17)└─ storage/<user>/<random-id>: file contents
                                                     │            avatars/, backups/, tls/
                                                     └─ authentik (OIDC): token exchange via libcurl
```

## Design choices
- **Modular C++, no framework soup.** It uses Crow (HTTP + WebSocket, header-only, vendored in `libs/`), nlohmann/json, OpenSSL, SQLite and libcurl. One binary of ~2.8 MB that idles at ~15 MB of RAM.
- **TLS in the daemon.** No reverse proxy is needed. It makes its own certificate, or uses a Tailscale one.
- **The server is not trusted with encrypted data.** Notes, and files when encryption is on, are encrypted in the browser. The server stores and serves opaque bytes and can't read them.
- **One small route module per feature.** Each `src/routes/*.cpp` registers its own endpoints. `main.cpp` wires them up.
- **Push, don't poll.** Changes are announced over one WebSocket per tab. Clients re-fetch only the list that changed.

## Source map
| Path | What it does |
|---|---|
| `src/main.cpp` | loads config, opens the database, sets up TLS, registers every route module, starts Crow, shuts down gracefully on SIGTERM / SIGINT |
| `src/core/config.cpp` | `KEY=VALUE` config loader |
| `src/http/middleware.cpp` | `SecurityMiddleware`: per-IP rate limit + ban, same-origin check for state-changing browser requests, CORS, security headers (CSP, HSTS, frame-deny, nosniff), request log line |
| `src/security/` | `crypto` (PBKDF2, SHA-256, HMAC, random, constant-time compare), `request_auth` (session / API key lookup), `rate_limiter` (token buckets, trusted-proxy IP resolution, per-account login backoff), `tls` (certificate generation, Tailscale cert), `oidc` (discovery, PKCE, token exchange, ID token checks), `e2e_keys` (key material for CLI-created admins), `sanitizer` |
| `src/storage/file_store.cpp` | blob storage: `storage/<userId>/<random hex>`, owner-only permissions, streaming + Range reads |
| `src/db/database.cpp` | every SQL statement (prepared, bound), schema + migrations at startup |
| `src/routes/auth.cpp` | register, login, logout, me, prefs, password change, API keys, salt |
| `src/routes/oidc.cpp` | SSO start / callback / identities |
| `src/routes/devices.cpp` | trusted devices, first-time key setup |
| `src/routes/fs.cpp` | folder tree, folders, file rename / move / star, search, recent, starred, usage |
| `src/routes/files.cpp` | direct upload, list, download, inline content (safe types only), delete |
| `src/routes/uploads.cpp` | resumable chunked uploads, stale-upload cleanup |
| `src/routes/notes.cpp` | notes |
| `src/routes/profile.cpp` | profile pictures |
| `src/routes/storage.cpp` | storage requests (user + admin) |
| `src/routes/admin.cpp` | users, remove / restore / wipe, sign-up requests, invites |
| `src/routes/events.cpp` | `/api/events` WebSocket + `notifyUser` / `notifyAdmins` |
| `src/routes/static_files.cpp` | serves `web/` with traversal protection |
| `src/cli/admin_cli.cpp` | `cloud_serv admin create-admin` |
| `include/storage/user_lock.h` | one lock per account around quota check + write |
| `web/index.html`, `style.css` | the app shell and the glass theme |
| `web/app.js` | the whole client: auth + key derivation, crypto, file manager, previews, uploads, zip writer, notes, settings, admin, routing, live updates |
| `web/sw.js` | service worker: caches the app shell (never API data) |
| `Companion-apps/cli/` | `cloudctl` (server management), `cloud` (client) |
| `tests/` | the test suite (bash + curl + node), mock OIDC provider |

## Data model (SQLite)
| Table | Holds |
|---|---|
| `users` | email, display name, password hash (PBKDF2 of the client-derived auth key), role, status (`active` / `pending` / `suspended` / `removed`), quota, encryption preference, wrapped data keys (password + recovery), KDF salt |
| `sessions` | SHA-256 of each session token, expiry |
| `api_keys` | SHA-256 of each key, display prefix, name, last used |
| `user_identities` | linked SSO identities (issuer + subject) |
| `devices` | trusted browsers: public key, status, data key wrapped to that device |
| `invites` | SHA-256 of one-time codes, label, expiry, used by |
| `folders` | tree (`parent_id`), plain or encrypted name, starred |
| `files` | folder, plain or encrypted name + mime, display size, **`stored_size`** (bytes on disk, used for quota), storage key, wrapped file key, starred |
| `upload_sessions` | unfinished chunked uploads: bytes received, last activity |
| `notes` | encrypted title + body |
| `storage_requests` | who, attempted upload, amount asked, status, decided by |
| `removed_users` | accounts an admin removed (reason, backup location) |
| `app_meta` | internal settings (e.g. the decoy-salt key) |

Each request opens its own SQLite connection (WAL mode), guarded by a reader/writer lock. Every query that touches a user's data includes `user_id = ?`, so one account can't reach another's rows by guessing IDs. The tests and the audit script check this.

## Request lifecycle
1. **Middleware:** resolve the client IP (trusted proxies only) and rate-limit it. Reject cross-origin state-changing browser requests.
2. **Route:** authenticate (session or API key, depending on the route), validate the input, do the work.
3. **Changes:** call `notifyUser` / `notifyAdmins` and every open tab of that person refreshes the affected list.
4. **Middleware:** add the security headers, write one log line.

## Encryption in one paragraph
The browser derives two keys from the password with PBKDF2: an **auth key** (sent instead of the password; the server hashes it again) and a **key-encryption key** that never leaves the browser.
- A random **data key** (DEK) is wrapped by that key, and separately by the **recovery key**. Only the wrapped forms are stored.
- Each encrypted file gets its own key, wrapped by the DEK, and is encrypted in chunks (AES-256-GCM, STREAM construction) so large files stream.
- **Trusted devices** hold a non-extractable P-256 key in IndexedDB. Approval wraps the DEK to it (ECDH + HKDF + AES-GCM), so an approved device unlocks without the password.

Full details: [SECURITY.md](SECURITY.md) and [CRYPTO_SPEC.md](CRYPTO_SPEC.md).

## Upload paths
- **Up to 8 MB (web) / `MAX_BODY_SIZE`:** one `POST /api/files`.
- **Larger:** `uploads/init` → `PUT` chunks with `X-Offset` → `complete`. Resumable after a disconnect: the server reports how much it has. Per-account locking means parallel uploads can't jointly exceed the quota or double-write a chunk.

## Testing
`bash tests/run.sh` builds and runs the whole suite: every test file starts its own throwaway server.
- **Areas covered:** auth, crypto, files, folders, uploads, races, quota, notes, OIDC (mock provider), devices, sign-up, events, profile, admin, rate limiting, TLS, security.
- **Separate checks:** `scripts/security-audit.sh` is an attack battery. The project has also been run under AddressSanitizer + UBSan and fuzzed (see [SECURITY.md](SECURITY.md#security-sweeps)).
