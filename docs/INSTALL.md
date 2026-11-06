# Installing cloud-serv

Three ways to run it, from most to least recommended:

1. **As a service with `deploy.sh`.** For a Proxmox CT, VM or any Debian/Ubuntu box. Guided setup, systemd, hardening, management tool.
2. **From a checkout.** For development or a quick try on your own PC.
3. **Docker.** If you already run everything in containers.

## Requirements

| | Minimum | Comfortable |
|---|---|---|
| OS | Debian 12/13, Ubuntu 22.04+ (anything with systemd + apt for `deploy.sh`) | Debian 13 CT |
| CPU / RAM | 1 core, 256 MB (idle use is ~15 MB) | 2 cores, 512 MB (compiling wants ~1 GB once) |
| Disk | room for your files + ~50 MB | a separate data disk or bind mount for `/var/lib/cloud-serv` |
| Network | a LAN IP | Tailscale for access from anywhere |

Build dependencies (installed by `deploy.sh` for you): `g++ make libasio-dev libssl-dev libsqlite3-dev libcurl4-openssl-dev`.

---

## 1. Install as a service (recommended)

### On your PC: build the package
```bash
cd cloud-serv
./package.sh                     # -> cloud-serv-deploy.zip (code only: no config, data or keys)
scp cloud-serv-deploy.zip root@<server>:/opt/
```

### On the server: install
```bash
cd /opt && unzip -o cloud-serv-deploy.zip && cd cloud-serv
./deploy.sh
```

It asks:

| Question | Default | Meaning |
|---|---|---|
| Port | `8443` | HTTPS port. Below 1024 works too (the service gets just that one capability). |
| Sign-up mode | `requests` | `closed`: only you or one-time invites. `requests`: anyone can ask, you approve on the Admin page. `code`: anyone with a shared code (generated and shown once). |
| Default storage (GB) | `0` | Quota for new accounts. `0` = unlimited. Change any account later on the Admin page. |
| Encrypt files by default | `false` | `true` = new users' files are end-to-end encrypted in the browser. Each user can switch it in Settings. |
| authentik / OIDC | no | Issuer URL, client ID and secret for "Sign in with authentik". See [authentik](#sign-in-with-authentik). |
| Create admin now | yes | Your account. Asks for a password, then saves a **recovery key** file. |

Then it builds, creates the `cloudserv` system user and folders, installs and starts the service, and prints the addresses to open.

> **The recovery key** is saved to `/etc/cloud-serv/recovery-<date>.txt`. It's the only way into your encrypted data if you forget your password. Copy it into a password manager and delete the file.

No questions (for scripts): `CS_PORT=8443 CS_SIGNUP=closed CS_QUOTA_GB=50 ./deploy.sh --yes`, then `cloudctl admin you@example.com`.

### What goes where
| Path | What | Owner / mode |
|---|---|---|
| `/opt/cloud-serv/` | code, binary, web app | root |
| `/etc/cloud-serv/config.env` | settings + secrets | `root:cloudserv 0640` |
| `/etc/cloud-serv/install.env` | where things are (read by `cloudctl`) | `0644` |
| `/var/lib/cloud-serv/` | database, files, profile pictures, account backups, TLS | `cloudserv 0700` |
| `/etc/systemd/system/cloud-serv.service` | the service | root |
| `/usr/local/bin/cloudctl`, `/usr/local/bin/cloud` | management tool, client | links into `/opt/cloud-serv` |

The service runs as `cloudserv` with no root rights, a read-only system and write access only to `/var/lib/cloud-serv` (`NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`, ...).

### Proxmox CT notes
- An **unprivileged** Debian 13 CT is fine: 2 cores, 512 MB RAM, 8 GB root disk.
- Put your files on a bigger disk with a mount point at `/var/lib/cloud-serv`. On the host: `pct set <id> -mp0 <storage>:<size>,mp=/var/lib/cloud-serv`. **Do this before running `deploy.sh`**, so the folders get created on it.
- Give it a static IP or a DHCP reservation, so the address stays put.
- Run `cloudctl backup` on a schedule, or include the CT in PBS backups (stop mode or snapshot both work: SQLite is crash-safe).

### Updating
On your PC, run `./package.sh` and copy the zip over. Then on the server:
```bash
cloudctl update /opt/cloud-serv-deploy.zip
```
It saves a copy of the database first, installs the new code, rebuilds and restarts. Your config and data are never touched. Database changes apply themselves on startup.

### Uninstalling
```bash
cd /opt/cloud-serv && ./deploy.sh --uninstall     # removes the service + tools
# your data is kept: delete /var/lib/cloud-serv and /etc/cloud-serv yourself if you mean it
```

---

## 2. Run from a checkout (development)

```bash
make
cp -n config.env.example config.env               # then edit: PORT, TLS_ENABLED, ...
./cloud_serv admin create-admin --email you@example.com --recovery-key-file ~/cloud-serv-recovery.txt
./cloud_serv config.env
```
Open `https://localhost:<PORT>`. Data goes to `./data/`. Stop it with Ctrl+C, or send `SIGTERM` (graceful).

Tests: `bash tests/run.sh` (builds, then runs the whole suite on throwaway servers).

---

## 3. Docker

```bash
docker build -t cloud-serv .
docker run -d --name cloud-serv -p 8443:8443 \
  -v /srv/cloud-serv/config.env:/app/config.env:ro \
  -v /srv/cloud-serv/data:/app/data \
  cloud-serv
docker exec -it cloud-serv ./cloud_serv admin create-admin --email you@example.com
```
Set `PORT=8443` and keep the `data/...` paths in the mounted config. `cloudctl` is for the systemd install; with Docker use `docker logs` and back up the `data` volume.

---

## HTTPS and certificates

cloud-serv serves HTTPS itself (no nginx needed):

- **Default:** a self-signed certificate is generated on first start. It covers `localhost`, the box's IPs and its Tailscale IP. Browsers warn once. The `cloud` client pins it at login.
- **Browser-trusted, via Tailscale (recommended):** turn on MagicDNS and HTTPS certificates in the Tailscale admin console, then run:
  ```bash
  cloudctl cert --timer     # gets https://<box>.<tailnet>.ts.net cert, renews monthly
  ```
  With a trusted certificate, installing the web app (PWA) and offline mode work without warnings on phones too.
- **Behind your own reverse proxy:** set `TLS_ENABLED=false` and `BIND_ADDRESS=127.0.0.1`, put the proxy's IP in `TRUSTED_PROXIES`, and make the proxy pass WebSockets (`/api/events`) through.

## Remote access with Tailscale
```bash
scripts/setup-tailscale.sh       # installs Tailscale and logs in (prints a URL)
cloudctl url                     # shows the LAN + Tailscale addresses
```
Nothing needs opening on your router. To share with someone outside your tailnet, use Tailscale's node sharing.

## Sign in with authentik
1. In authentik, create an **OAuth2/OpenID provider** with:
   - client type **Confidential**;
   - redirect URI `https://<address>:<port>/api/auth/oidc/callback`, one per address you use (LAN, Tailscale name);
   - scopes `openid email profile`, plus a **groups** claim if you want group gating.
2. Create an **application** using that provider. Its slug forms the issuer URL: `https://auth.example.com/application/o/<slug>/`.
3. Make a group (default name `cloud-serv-users`) and put the people who should get accounts in it.
4. Set `OIDC_ISSUER`, `OIDC_CLIENT_ID` and `OIDC_CLIENT_SECRET` (`cloudctl config edit`), then restart.

The login page then shows a "Sign in with authentik" button:
- **People in the group** get an account automatically on first sign-in.
- **People with an existing account** link it under **Settings > Sign-in methods**. Accounts are never matched by email: that would let anyone who controls an IdP email take over an account.
