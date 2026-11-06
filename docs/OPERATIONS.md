# Running cloud-serv: operations runbook

For a service install made with `deploy.sh`. Every command is `cloudctl` (details in [COMPANION_APPS.md](COMPANION_APPS.md#cloudctl-server-management)).

## Everyday
| Want to | Do |
|---|---|
| See if it's healthy | `cloudctl status` (or `cloudctl doctor` for the full checklist) |
| See what's happening | `cloudctl logs -f` |
| Find the address | `cloudctl url` |
| Approve people / storage | web app > your picture > **Admin** (the red count shows what's waiting) |
| Add another admin | `cloudctl admin someone@example.com`, or promote an existing user on the Admin page |
| Change a setting | `cloudctl config edit` (restarts and checks it came back) |

## Monitoring
- **Health endpoint:** `GET /api/health` → `{"status":"ok"}`. No login needed, cheap, fine for Homepage, Uptime Kuma or a load balancer.
- **Logs** (journald) have one line per request: client IP, method, path, status, size, duration. 4xx/5xx lines are logged at WARN. Search them with `cloudctl logs 1000 | grep WARN`.
- **What to watch:**
  - repeated `401` on `/api/auth/login` from one IP (password guessing: it gets throttled, then banned);
  - `429` bursts (a client misbehaving);
  - any `500` (please report it: the fuzz tests expect none).

## Backups
| Layer | How | Restores |
|---|---|---|
| App backup | `cloudctl backup <dir>` nightly by cron (example in COMPANION_APPS.md) | `cloudctl restore <file>` onto any install |
| Proxmox | PBS backup of the CT (snapshot mode is fine: SQLite in WAL mode is crash-safe) | restore the CT |
| Before updates | automatic: `cloudctl update` saves `backups/pre-update-<date>.db` | copy it back over `cloud.db` with the service stopped |

What a backup can and can't do:
- **Normal files** are readable inside the backup.
- **Encrypted files and notes** stay encrypted. They come back intact for their owners, but nobody can read them from the backup alone, and that's by design.
- **Users** must keep their own recovery key. Without both password and recovery key, their encrypted data is gone, backup or not.
- **Test a restore now and then.** Install a scratch CT with `deploy.sh`, `cloudctl restore` the latest backup, sign in.

## Updating
```bash
# on your PC
./package.sh && scp cloud-serv-deploy.zip root@<server>:/opt/
# on the server
cloudctl update /opt/cloud-serv-deploy.zip
```
Takes a database safety copy, replaces the code, rebuilds, restarts. Database migrations run on startup and only ever add columns. To roll back, deploy the previous zip the same way; if needed, put the pre-update database copy back.

## Graceful shutdown
`cloudctl stop` (or `systemctl stop cloud-serv`) sends SIGTERM:
1. no new connections;
2. in-flight requests finish (up to 30 s);
3. the database closes cleanly.

Shutting down the CT or host does the same. Interrupted uploads resume from the client later. Uploads left idle for 24 h are cleaned up.

## Security maintenance
- **Keep the OS patched:** `apt update && apt upgrade` in the CT, then `cloudctl restart`.
- **API keys:** users see and revoke theirs in Settings. Keys show when they were last used.
- **Lost device:** the owner revokes it in Settings > Devices. Changing the password signs out all other sessions.
- **Bad actor:** Admin > Users > suspend (instant: their sessions stop working). Remove takes their data into a restorable backup. Wipe deletes it permanently.
- **OIDC secret leaked:** rotate it in authentik, `cloudctl config edit`, paste the new one.
- **Run the attack battery after big changes:** `scripts/security-audit.sh` on your PC.

## Troubleshooting
| Symptom | Likely cause | Fix |
|---|---|---|
| `cloudctl status` says not running | bad config or port in use | `cloudctl logs 50`. Fix the line it names (`cloudctl config edit`), or free the port. |
| Starts, but unreachable from other machines | `BIND_ADDRESS=127.0.0.1`, or a firewall | set `0.0.0.0`; open the port in the CT / host firewall |
| Certificate warning on every device | self-signed certificate | `cloudctl cert --timer` (Tailscale), or accept it once per device |
| `cloudctl cert` fails | MagicDNS or HTTPS certs off in Tailscale | Tailscale admin > DNS > enable both, then retry |
| "Sign in with ..." errors | redirect URI not registered for the address you used, or the clock is off | add `https://<that address>:<port>/api/auth/oidc/callback` in authentik. Check `timedatectl`. |
| A user's storage looks wrong | quota counts real bytes on disk, including unfinished uploads | wait 24 h for idle uploads to expire, or have them cancel stuck uploads |
| "too many devices waiting" | someone left approval requests open | they revoke stale ones in Settings > Devices |
| Disk filling up | uploads + admin "remove" backups | `cloudctl users` for who uses what; wipe removed accounts you don't need back |
| `cloudctl doctor`: database integrity FAIL | disk problem or unclean power loss on a bad disk | stop the service, `cloudctl restore` the latest backup, check the disk |
