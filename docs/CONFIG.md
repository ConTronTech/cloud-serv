# Configuration reference

All settings live in one `KEY=VALUE` file: `/etc/cloud-serv/config.env` for a service install, or `config.env` in a checkout. Lines starting with `#` are comments.

- **Changing settings:** `cloudctl config edit` opens the file and restarts the service when you save. `cloudctl config show` prints it with secrets hidden.
- **Defaults:** a missing key uses the default in the table. `config.env.example` has every key with comments.
- **Secrets:** the file holds the OIDC client secret and any shared sign-up code. Keep it `0640 root:cloudserv` (`cloudctl doctor` checks).

## Server
| Key | Default | What it does |
|---|---|---|
| `PORT` | `8080` (`deploy.sh` sets 8443) | Port to listen on. |
| `BIND_ADDRESS` | `0.0.0.0` | `0.0.0.0` = all interfaces (LAN + Tailscale). `127.0.0.1` = only this box (behind a reverse proxy). |
| `WEB_DIR` | `web` | Folder with the web app, served at `/`. |
| `LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARN` or `ERROR`. `INFO` logs one line per request (IP, method, path, status, size, time), never bodies or tokens. |
| `TRUSTED_PROXIES` | empty | IPs allowed to set `X-Forwarded-For`. Only needed behind a reverse proxy. Otherwise leave it empty so clients can't fake their IP. |
| `CORS_ORIGINS` | empty | Extra web origins allowed to call the API. Empty = same-origin only (correct for the built-in web app). |

## Storage and data
| Key | Default | What it does |
|---|---|---|
| `DB_PATH` | `data/cloud.db` | SQLite database: accounts, file list, notes, settings. |
| `STORAGE_DIR` | `data/storage` | File contents, one private folder per account, random file names on disk. |
| `TREE_ROOT` | empty (off) | Real-folder storage root. An account switched with `cloudctl tree <email> <dir>` keeps its files as a normal folder tree at `TREE_ROOT/<dir>/` (names readable on disk, no end-to-end encryption). See [REAL_FOLDERS.md](REAL_FOLDERS.md). |
| `TRASH_DAYS` | `30` | Real folders: deleted items wait in `<dir>/.trash/<YYYY-MM-DD>/` this long. `0` = delete straight away. |
| `TREE_SCAN_MINUTES` | `15` | Real folders: how often files added/changed/removed outside the app are picked up (also at startup and on `cloudctl rescan`). |
| `AVATAR_DIR` | `data/avatars` | Profile pictures. |
| `BACKUP_DIR` | `data/backups` | Where an admin "Remove account" puts that account's data so it can be restored. |
| `MAX_BODY_SIZE` | `268435456` (256 MB) | Largest single request. Bigger files are uploaded in chunks automatically. |
| `MAX_FILE_MB` | `5120` (5 GB) | Largest single file. |
| `DEFAULT_STORAGE_QUOTA_GB` | `0` | Quota for new accounts, `0` = unlimited. Admins change individual accounts on the Admin page. |

Quotas count the bytes actually stored on disk, including uploads still in progress. Uploads left unfinished for 24 hours are deleted.

## HTTPS
| Key | Default | What it does |
|---|---|---|
| `TLS_ENABLED` | `true` | Serve HTTPS. `false` = plain HTTP (development, or behind a TLS proxy). |
| `TLS_CERT_PATH` / `TLS_KEY_PATH` | `data/tls/server.crt` / `.key` | Certificate files. Created automatically if missing. |
| `TLS_PREFER_TAILSCALE_CERT` | `true` | On startup, try `tailscale cert` for a browser-trusted certificate. When the service runs without root this usually can't work, so use `cloudctl cert` instead (it runs as root and the server keeps the result). |

A self-signed certificate is regenerated when it's missing, near expiry, or doesn't cover the box's current Tailscale IP. A real (non-self-signed) certificate is never replaced.

## Accounts and sign-up
| Key | Default | What it does |
|---|---|---|
| `SESSION_SECONDS` | `2592000` (30 days) | How long a sign-in lasts. |
| `REGISTRATION_REQUESTS` | `false` | `true` = anyone can ask for an account. It waits for an admin's approval on the Admin page (at most 25 waiting). |
| `REGISTRATION_INVITE_CODE` | empty | A shared sign-up code. Empty = off. One-time invites from the Admin page work regardless and are the better option. |
| `FILES_ENCRYPT_DEFAULT` | `false` | Whether accounts that haven't chosen get end-to-end encrypted uploads. Each user can switch it in Settings. It only affects new uploads. |
| `REMOVED_ACCOUNT_NOTICE` | "Your data has been temporarily removed..." | Shown when someone signs in to an account an admin removed. |
| `APPEAL_CONTACT` | empty | Contact shown alongside that notice. |

Wrong codes, closed sign-up and taken emails all get the same answer, so sign-up can't be used to find out who has an account.

## Sign in with an OpenID Connect provider (authentik, Keycloak, ...)
| Key | Default | What it does |
|---|---|---|
| `OIDC_ISSUER` | empty | Issuer URL, e.g. `https://auth.example.com/application/o/cloud-serv/`. Empty hides the button. |
| `OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET` | empty | From the provider. |
| `OIDC_ALLOWED_GROUP` | empty (example: `cloud-serv-users`) | Only members get a new account on first sign-in. Empty = anyone the provider lets through. Existing accounts must link first in Settings either way. |
| `OIDC_BUTTON_LABEL` | `SSO` | Button text ("Sign in with ..."). |
| `OIDC_REDIRECT_URIS` | empty | Optional allowlist of exact callback URLs, comma separated. Empty = built from the address the browser used. Set it if you expose the server under unexpected host names. |

## Rate limiting (per client IP)
| Key | Default | What it does |
|---|---|---|
| `RATE_LIMIT_ENABLED` | `true` | Master switch. |
| `READ_RPM` / `WRITE_RPM` | `1200` / `600` | Sustained requests per minute for reads and writes. |
| `BURST_SIZE` | `200` | How many requests can arrive at once (a folder of 200 files uploads without waiting). |
| `BAN_THRESHOLD` / `BAN_DURATION` | `100` / `300` s | After this many throttled requests, the IP is blocked for this long. |

Failed sign-ins also have their own per-account backoff (each failure makes the next attempt wait longer), separate from these per-IP limits.
