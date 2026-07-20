# cloud-serv

A self-hosted personal cloud suite (files now; notes / contacts / calendar later),
built from scratch in **modular C++ (Crow)**. One API server + a shared web client,
with native apps added later. Runs on your own PC; reachable remotely over Tailscale.

## Status

**Steps 1–2 (done):** multi-user backend + an installable web client (PWA).
Security-audited (see `scripts/security-audit.sh`).

Roadmap:
1. ✅ Backend: multi-user auth (sessions + API keys) + files.
2. ✅ Web PWA client (browser + Linux install + Android home-screen app).
3. 🚧 Suite modules: ✅ notes → ⬜ contacts → ⬜ calendar.
4. ⬜ Tailscale remote access + HTTPS (front with a reverse proxy).
5. ⬜ (Optional) native Android app.

## Architecture

```
Web PWA / Android / Linux  →  HTTP/REST  →  API server (C++ / Crow)
                                              ├── SQLite (metadata: users, keys, files)
                                              └── Disk   (file blobs, per-user dirs)
```

Built on reusable security cores (adapted from the project-tracker stack):
`SecurityMiddleware` (rate limiting, CSRF, CORS, security headers, request
logging), `Sanitizer`, `Validator`, `RateLimiter` (with trusted-proxy XFF
resolution). The multi-user layer adds:

- **Accounts** — passwords hashed with **PBKDF2-HMAC-SHA256** (OpenSSL), 200k iterations.
- **Sessions** — opaque random tokens; only their SHA-256 is stored.
- **API keys** — `csk_…` keys for programmatic / mobile / CLI use; shown once,
  stored only as SHA-256, with a display prefix. Revocable.
- Everything a user owns is scoped by `user_id`; one user can't touch another's data.

## Build & run

Dependencies (Ubuntu/Debian): `libasio-dev` (Crow), `libssl-dev` (crypto),
`libsqlite3-dev` (database). Crow + nlohmann/json are vendored in `libs/`.

```bash
make
./cloud_serv config.env      # listens on http://0.0.0.0:8080
```

Then open **http://localhost:8080** — the web client (PWA) is served same-origin
by the C++ server, so there's no separate build step or CORS setup. On Chrome/Edge
(desktop or Android) use "Install app" to add it to your home screen / app menu.

Data (SQLite DB + uploaded blobs) is written under `data/` and is gitignored.
Configuration lives in `config.env`. Or run in Docker: `docker build -t cloud-serv .`

## Web client (PWA)

`web/` is a dependency-free vanilla-JS PWA (no build step): login/register, a
drag-and-drop file manager (upload, download, delete), and offline app-shell
caching via a service worker. Filenames are always rendered with `textContent`
(never `innerHTML`), so a filename can't inject HTML.

## Testing / security

```bash
make && ./scripts/security-audit.sh   # 16-case attack + regression battery
```

Covers SQL injection, path traversal (API + static), cross-user IDOR, auth
bypass, input validation, and logout revocation. Runs on a throwaway DB/port,
so it never touches your real data.

## API quick reference

| Method | Path                     | Auth | Purpose                                   |
|--------|--------------------------|------|-------------------------------------------|
| GET    | `/api/health`            | no   | Liveness check                            |
| POST   | `/api/auth/register`     | no   | Create account → `{token, user}`          |
| POST   | `/api/auth/login`        | no   | Log in → `{token, user}`                  |
| GET    | `/api/auth/me`           | yes  | Current user                              |
| POST   | `/api/auth/logout`       | yes  | Revoke current session token              |
| POST   | `/api/auth/api-keys`     | yes  | Create API key (**full key shown once**)  |
| GET    | `/api/auth/api-keys`     | yes  | List keys (prefixes only)                 |
| DELETE | `/api/auth/api-keys/<id>`| yes  | Revoke a key                              |
| POST   | `/api/files`             | yes  | Upload small file (raw body + `X-Filename`)|
| GET    | `/api/files`             | yes  | List your files                           |
| GET    | `/api/files/<id>`        | yes  | Download (streamed, attachment)           |
| GET    | `/api/files/<id>/content`| yes¹ | Inline content, **Range/206** for playback |
| DELETE | `/api/files/<id>`        | yes  | Delete                                    |
| POST   | `/api/uploads/init`      | yes  | Start chunked upload `{name,mime?,size?}` |
| GET    | `/api/uploads/<id>`      | yes  | Upload status (for resume)                |
| PUT    | `/api/uploads/<id>`      | yes  | Append chunk (raw body + `X-Offset`)      |
| POST   | `/api/uploads/<id>/complete` | yes | Finalize → `{file}`                   |
| DELETE | `/api/uploads/<id>`      | yes  | Abort chunked upload                      |
| GET    | `/api/notes`             | yes  | List notes (summaries)                    |
| POST   | `/api/notes`             | yes  | Create note `{title?,body?}`              |
| GET    | `/api/notes/<id>`        | yes  | Read note (full)                          |
| PUT    | `/api/notes/<id>`        | yes  | Update note                               |
| DELETE | `/api/notes/<id>`        | yes  | Delete note                               |

Authenticate with **either** `Authorization: Bearer <session-token>` (web login)
**or** `X-API-Key: <key>` (programmatic clients). ¹ The `content` endpoint also
accepts the **session cookie** (set at login), so `<video>`/`<audio>`/`<img>`
`src` work same-origin without a header.

**Large files & media:** any file type is accepted. Files over 8 MB upload in
resumable chunks (`init → PUT chunks → complete`); the `content` endpoint serves
HTTP Range requests (206) so video/audio stream and seek without a full download.
The web client previews images and plays video/audio inline.

## Try it with curl

```bash
API=localhost:8080

# register (returns a session token)
TOKEN=$(curl -s $API/api/auth/register -H 'content-type: application/json' \
  -d '{"email":"me@example.com","password":"supersecret"}' \
  | grep -o '"token":"[^"]*"' | cut -d'"' -f4)

# mint an API key for a device (shown once)
KEY=$(curl -s -X POST $API/api/auth/api-keys -H "authorization: Bearer $TOKEN" \
  -d '{"name":"phone"}' | grep -o '"key":"[^"]*"' | cut -d'"' -f4)

# upload a file using the API key
curl -s -X POST $API/api/files -H "X-API-Key: $KEY" \
  -H "X-Filename: photo.jpg" -H "content-type: image/jpeg" \
  --data-binary @photo.jpg

# list, then download id 1
curl -s $API/api/files -H "X-API-Key: $KEY"
curl -s $API/api/files/1 -H "X-API-Key: $KEY" -o out.jpg
```

## Layout

```
include/ src/
  core/        config loader
  http/        SecurityMiddleware (rate limit, CSRF, CORS, headers, logging)
  security/    crypto (PBKDF2/SHA-256/CSPRNG), request_auth, rate_limiter,
               sanitizer, validator
  db/          CloudDB (sqlite3 C API; shared_mutex read-many/write-one), models
  storage/     FileStore (per-user blobs on disk)
  routes/      auth.cpp (accounts + keys), files.cpp, notes.cpp, static_files.cpp (PWA)
  main.cpp     bootstrap
web/           the PWA (index.html, app.js, style.css, manifest, sw.js)
scripts/       security-audit.sh (attack + regression battery)
libs/          crow, nlohmann/json (vendored)
schema.sql     reference schema (CloudDB also creates tables at startup)
config.env     runtime configuration
```
