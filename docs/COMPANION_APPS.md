# Companion apps and setup tools

Everything around the server that makes it easy to install, run and use.

| Tool | Runs on | What for |
|---|---|---|
| [`package.sh`](#packagesh) | your PC | builds the deploy zip |
| [`deploy.sh`](#deploysh) | the server (root) | installs or updates the service, with a setup wizard |
| [`cloudctl`](#cloudctl-server-management) | the server | status, logs, users, backup / restore, update, certificates, health check |
| [`cloud`](#cloud-the-command-line-client) | any machine with Python 3 | upload, download and manage your files with an API key |
| `scripts/setup-tailscale.sh` | the server (root) | installs Tailscale and logs in |
| `scripts/security-audit.sh` | your PC | attack battery against a throwaway server (SQL injection, traversal, cross-user access, auth bypass) |
| `cloud_serv admin` | the server | built-in: create an admin account directly in the database |

The command-line tools live in `Companion-apps/cli/`. `deploy.sh` links them into `/usr/local/bin`.

---

## package.sh
```bash
./package.sh                 # cloud-serv-deploy.zip from the last commit
./package.sh --dirty out.zip # include uncommitted changes (testing only)
```
Packs every git-tracked file into `cloud-serv/` inside the zip, with a `VERSION` stamp. It refuses to run with uncommitted changes, so you always know what a server is running. **Never included:** `config.env`, `data/`, keys, recovery keys. It checks and aborts if any slip in.

## deploy.sh
Install, update and uninstall. See [INSTALL.md](INSTALL.md) for the walkthrough.
```bash
./deploy.sh                  # first run: wizard; later runs: rebuild + restart, config and data kept
./deploy.sh --yes            # no questions (defaults, or CS_PORT / CS_SIGNUP / CS_QUOTA_GB / CS_ENCRYPT)
./deploy.sh --no-build       # binary already built
./deploy.sh --uninstall      # remove the service + tools, keep data + config
```

---

## cloudctl: server management
Run `cloudctl` with no arguments for a numbered menu, or use commands. Read-only commands work for any user who can read the files. Anything that changes the system needs root.

| Command | Does |
|---|---|
| `cloudctl status` | running?, health check, version, accounts (and how many wait for approval), files, disk use |
| `cloudctl start` / `stop` / `restart` | control the service. Stop is graceful: requests finish and the database closes cleanly. |
| `cloudctl logs [-f] [N]` | last N log lines (default 100), `-f` to follow |
| `cloudctl url` | every address it can be opened on: localhost, LAN IPs, Tailscale name + IP |
| `cloudctl users` | accounts with role, status, used / quota |
| `cloudctl admin <email>` | create another admin. Asks for a password, saves the recovery key to `/etc/cloud-serv/recovery-<date>.txt` (root-only). |
| `cloudctl backup [dir]` | full backup to `cloud-serv-<date>.tar.gz` (see below) |
| `cloudctl restore <file>` | restore a backup. The current data is moved aside first, not deleted. |
| `cloudctl update <zip>` | install a new deploy zip: database safety copy, new code, rebuild, restart |
| `cloudctl config show` / `edit` | show (secrets hidden) or edit, then restart and check it came back |
| `cloudctl cert [--timer]` | browser-trusted HTTPS certificate from Tailscale. `--timer` renews monthly. |
| `cloudctl doctor` | checks service, port, permissions, ownership, disk space, certificate expiry, database integrity, Tailscale |
| `cloudctl version` | installed version |

### Backups
`cloudctl backup` makes one `.tar.gz` (mode `0600`) containing:
- **the database**, copied with SQLite's online backup, so it's consistent while the server runs;
- **every account's files**, profile pictures and admin "removed account" backups;
- **the TLS certificate**;
- **the config**, including secrets: keep backups private.

Files a user chose to encrypt stay encrypted inside the backup. A backup can't open them, but restoring gives them back to their owner intact.

Schedule it with cron as root, e.g. nightly to a mounted drive:
```bash
0 3 * * * /usr/local/bin/cloudctl backup /mnt/backup/cloud-serv >/dev/null && find /mnt/backup/cloud-serv -name 'cloud-serv-*.tar.gz' -mtime +14 -delete
```
`cloudctl restore` puts back the data but **keeps your current config**, saving the backup's copy as `/etc/cloud-serv/config.from-backup` for you to compare. That way, restoring onto a new box doesn't overwrite its ports or paths.

**Moving to a new server:** on the old box run `cloudctl backup`. On the new box run `deploy.sh`, copy the backup over, then `cloudctl restore <file>`.

---

## cloud: the command-line client
A single Python 3 file with no dependencies. It works on Linux and macOS, and on Windows with Python. Copy `Companion-apps/cli/cloud` anywhere on your `PATH`.

### Log in once
1. In the web app: **Settings > API keys > Create key**. Copy the `csk_...` key.
2. Then:
   ```bash
   cloud login https://my-cloud.tailnet.ts.net:8443
   ```
   It asks for the key, hidden.
3. If the server uses its own (self-signed) certificate, `cloud` shows the certificate's fingerprint and the command to check it on the server. Once you trust it, that exact certificate is **pinned**. If the certificate ever changes unexpectedly, `cloud` refuses to connect instead of carrying on.

Settings are stored in `~/.config/cloud-serv/` (folder `0700`, files `0600`). For scripts, set `CLOUD_URL` and `CLOUD_KEY` instead.

### Commands
| Command | Does |
|---|---|
| `cloud ls [-l] [path]` | list a folder (`-l`: size, date, `*` = starred) |
| `cloud tree [path]` | the whole tree with sizes and a total |
| `cloud put <file...> [folder]` | upload files into a folder (default Home) |
| `cloud put -r <dir...> [folder]` | upload folders with everything inside. Re-running merges into the existing folders. |
| `cloud get <path> [local]` | download a file |
| `cloud get -r <folder> [local]` | download a folder tree |
| `cloud mkdir <path>` | create folders, parents included |
| `cloud mv <path> <new-name>` | rename |
| `cloud mv <path> <folder>` | move into an existing folder (`/a/b/newname` moves and renames) |
| `cloud rm <file>` / `cloud rm -r [-y] <folder>` | delete (folders ask first unless `-y`) |
| `cloud star` / `unstar <path>` | star / unstar |
| `cloud search <text>` / `recent` / `starred` | find things |
| `cloud usage` | used / quota |
| `cloud logout` | forget the key (revoke it in the web app too) |

Paths start at `/` (your Home): `/Photos/2026/beach.jpg`. To pick an item by number, use `#id` (shown by `search` and for encrypted items).

**How transfers work:**
- Files over 8 MB upload in 16 MB pieces. If the connection drops, the upload resumes where the server stopped.
- An interrupted or failed upload is cancelled on the server, so it doesn't hold your quota.
- Downloads write to `name.part` and rename to the real name only once complete.
- Rate-limit replies are retried automatically with backoff.

**Encrypted files.** Files you uploaded with *Encrypt my files* on show as `[encrypted #id]`. Only your browser holds their key, so `cloud` can list, move, star and delete them, but can't download them. `get -r` skips them and says so. Uploads from `cloud` are stored unencrypted.

### Examples
```bash
cloud put -r ~/Pictures/Trip /Photos              # back up a folder
cloud get -r /Photos/Trip ~/restore               # fetch it back
CLOUD_URL=https://nas:8443 CLOUD_KEY=$(cat ~/.cloudkey) cloud put report.pdf /Work   # from a script
```

Errors are plain: wrong or revoked key, quota exceeded (use *Request more storage* in the web app), not found, or the server unreachable. The exit code is non-zero on any failure.
