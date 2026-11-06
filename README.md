# cloud-serv

[![CI](https://github.com/ConTronTech/cloud-serv/actions/workflows/ci.yml/badge.svg)](https://github.com/ConTronTech/cloud-serv/actions/workflows/ci.yml)

A self-hosted personal cloud, built from scratch in **modular C++ (Crow)**. Files, folders and notes for you and the people you invite, on a server you own, reachable over your LAN or Tailscale. Optional end-to-end encryption means even the server can't read what you protect.

One ~2.8 MB binary, ~15 MB of RAM at idle, serves HTTPS, the API, live updates and the web app. No database server, no reverse proxy, no Node.

## Features
- **Files:**
  - any type, up to 5 GB each;
  - folder uploads by drag-and-drop;
  - resumable chunked uploads;
  - previews (images, video with seeking, audio, PDF, text);
  - download whole folders as `.zip`;
  - right-click menus, search, Recent, Starred, grid and list views.
- **Notes:** always end-to-end encrypted.
- **Encryption your way:** files are normal (easy backups) or end-to-end encrypted in the browser, per account. Trusted devices unlock without the password; a recovery key covers everything.
- **Accounts:**
  - one-time invite codes, sign-up requests you approve, or "Sign in with authentik" (OIDC) with account linking;
  - profile pictures, password change that signs out other devices, API keys.
- **Admin page:**
  - approve sign-ups and storage requests, set quotas;
  - suspend, or remove / restore / wipe accounts.
  - Admins can never read encrypted data.
- **Storage requests:** when an upload doesn't fit, the user can skip files or ask for more. The admin sees exactly how much the upload needed.
- **Live everywhere:** changes appear on every open device instantly over a WebSocket. No polling, no refresh.
- **Installable web app (PWA):** browser, Linux desktop, Android home screen. Back/Forward work like normal pages.
- **Tools:** a one-command installer with a setup wizard, `cloudctl` for running it, and `cloud` for the command line.

## Quick start

**On a server or Proxmox CT** (Debian/Ubuntu):
```bash
./package.sh                                   # on your PC: builds cloud-serv-deploy.zip
scp cloud-serv-deploy.zip root@server:/opt/
ssh root@server
cd /opt && unzip -o cloud-serv-deploy.zip && cd cloud-serv && ./deploy.sh
```
It asks a few questions up front (port, sign-up mode, quota, encryption, authentik, your admin account), then builds, installs and starts on its own. Afterwards:
```bash
cloudctl            # menu: status, logs, users, backup, update, certificates, doctor...
```

**For development:**
```bash
make && cp -n config.env.example config.env
./cloud_serv admin create-admin --email you@example.com
./cloud_serv config.env                         # then open https://localhost:<PORT>
bash tests/run.sh                               # full test suite
```

**From the command line**, with an API key from Settings:
```bash
cloud login https://my-cloud.tailnet.ts.net:8443
cloud put -r ~/Pictures/Trip /Photos    &&    cloud get -r /Photos/Trip .
```

## Documentation
| Doc | For |
|---|---|
| [User guide](docs/USER_GUIDE.md) | using it: files, notes, encryption, devices, settings, admin |
| [Install](docs/INSTALL.md) | service install, Proxmox, Docker, HTTPS, Tailscale, authentik |
| [Configuration](docs/CONFIG.md) | every setting in `config.env` |
| [Operations](docs/OPERATIONS.md) | monitoring, backups, updates, troubleshooting |
| [Companion apps](docs/COMPANION_APPS.md) | `deploy.sh`, `package.sh`, `cloudctl`, `cloud` |
| [API](docs/API.md) | every endpoint, auth, live-update events |
| [Architecture](docs/ARCHITECTURE.md) | how it's built: modules, data model, request flow |
| [Security](docs/SECURITY.md) | threat model, encryption, what's verified, sweep results |
| [Crypto spec](docs/CRYPTO_SPEC.md) | exact formats for writing another client |
| [Admin API](docs/ADMIN_API.md) | roles, quotas, remove / restore / wipe in depth |
| [Roadmap](docs/ROADMAP.md) | what's next |

## Layout
```
src/            C++ server: routes/ (one module per feature), db/, security/, storage/, http/, cli/
include/        headers
web/            the web app (vanilla JS, no build step) + service worker
libs/           vendored Crow + nlohmann/json
Companion-apps/ cli/cloudctl (server management), cli/cloud (client)
scripts/        setup-tailscale.sh, security-audit.sh, wipe-data.sh
tests/          test suite: bash + curl + node, mock OIDC provider
deploy.sh       install / update / uninstall as a systemd service
package.sh      build the deploy zip
```

## Security in short
- **Accounts and credentials:**
  - passwords never leave the browser (a derived key is sent, and hashed again);
  - sessions and API keys are stored only as hashes;
  - every query is scoped to its owner.
- **Network:**
  - HTTPS with HSTS, a strict CSP, SameSite=Strict cookies and same-origin checks;
  - per-IP rate limits, per-account login backoff.
- **Testing:** sanitizer-checked, fuzzed, race-tested.
- **Service install:** runs in a tight systemd sandbox.

Details and the latest sweep results: [docs/SECURITY.md](docs/SECURITY.md).
