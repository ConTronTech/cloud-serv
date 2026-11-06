# HTTP API reference

Every endpoint the server has. JSON in and out unless noted. Errors are always `{"error": "..."}` with a matching HTTP status. For the exact encryption formats a second client must produce, see [CRYPTO_SPEC.md](CRYPTO_SPEC.md).

## Authentication
| Credential | How to send | Works on |
|---|---|---|
| **Session** (from login / register) | `Authorization: Bearer <token>`, or the `session` cookie the web app gets (HttpOnly, Secure, SameSite=Strict) | everything |
| **API key** (`csk_...`, Settings > API keys) | `X-API-Key: csk_...` | files, folders, uploads, notes, search, usage. Marked **K** below. |

API keys deliberately can't reach account, device, admin or live-update endpoints. A leaked key can touch files, not the account.

Browser requests that change something must be same-origin (`Origin` is checked). Rate limits and their `429` + `Retry-After` replies are described in [CONFIG.md](CONFIG.md#rate-limiting-per-client-ip).

Columns: **Auth** = `-` none, `S` session, `S/K` session or API key, `A` admin session.

## Health and setup
| Method | Path | Auth | Notes |
|---|---|---|---|
| GET | `/api/health` | - | `{"status":"ok","service":"cloud-serv"}` |
| GET | `/api/auth/signup-mode` | - | which sign-up options are on (shapes the Register form) |
| GET | `/api/auth/oidc/config` | - | `{enabled, label}` for the SSO button |

## Account
| Method | Path | Auth | Body / notes |
|---|---|---|---|
| GET | `/api/auth/salt?email=` | - | the key-derivation salt for an email. Unknown emails get a stable fake salt, so it doesn't reveal accounts. |
| POST | `/api/auth/register` | - | `{email, password, inviteCode?, displayName?, note?, salt, wrappedDek, wrappedDekRecovery}`. `password` is the client-derived auth key, never the raw password. Returns `{token, user}`, or `202 {"pending":true}` for a sign-up request. Closed / wrong code / taken email all give `403 "registration is not open"`. |
| POST | `/api/auth/login` | - | `{email, password}` → `{token, user, salt, wrappedDek, ...}`. `401` wrong, `403 {"code":"pending"\|"suspended"\|"data_removed"}`, `429` after repeated failures. |
| POST | `/api/auth/logout` | S | ends this session |
| GET | `/api/auth/me` | S | profile: email, name, role, quota, `encryptFiles`, `avatarVersion`, key material |
| PATCH | `/api/auth/me/prefs` | S | `{encryptFiles?: bool, displayName?: string(1-64)}` |
| POST | `/api/auth/password` | S | `{currentPassword, newPassword, salt, wrappedDek}`. Rewraps the data key; signs out every other session. |
| PUT | `/api/auth/me/avatar` | S | raw JPEG/PNG/WebP body, < 300 KB (content-sniffed, the Content-Type header is ignored) |
| GET / DELETE | `/api/auth/me/avatar` | S | the picture / remove it |
| GET | `/api/auth/api-keys` | S | your keys (prefix, name, created, last used; never the key) |
| POST | `/api/auth/api-keys` | S | `{name}` → `{key:"csk_..."}`, **shown once** |
| DELETE | `/api/auth/api-keys/<id>` | S | revoke |

### Single sign-on (OIDC)
| Method | Path | Auth | Notes |
|---|---|---|---|
| GET | `/api/auth/oidc/start?mode=login\|link` | - / S | redirects to the provider (PKCE S256, state + nonce). `link` attaches the identity to the signed-in account. |
| GET | `/api/auth/oidc/callback` | - | the provider returns here. It signs in, auto-creates the account (allowed group only) or links, then redirects to the app. |
| GET | `/api/auth/identities` | S | linked sign-in identities |
| DELETE | `/api/auth/identities/<id>` | S | unlink |

### Devices (encryption unlock without a password)
| Method | Path | Auth | Notes |
|---|---|---|---|
| GET | `/api/devices` | S | your devices, `pending` / `approved` |
| POST | `/api/devices` | S | `{name, publicKey, wrappedDek?}`. Register this browser's P-256 key. With `wrappedDek` (made by an unlocked device) it's approved at once. |
| GET | `/api/devices/<id>/key` | S | a device's public key, for the approving device to wrap the data key to |
| POST | `/api/devices/<id>/approve` | S | `{wrappedDek}`: the data key encrypted to that device |
| DELETE | `/api/devices/<id>` | S | revoke |
| POST | `/api/keys/init` | S | `{wrappedDekRecovery}`: first-time key setup for SSO-created accounts |

## Files and folders
| Method | Path | Auth | Body / notes |
|---|---|---|---|
| GET | `/api/fs?folder=<id>` | S/K | `{folders, files, breadcrumbs}`. `0` or no `folder` = Home. |
| POST | `/api/folders` | S/K | `{parentId, name}` (or `encName` for encrypted names) → `{folder}` |
| PATCH | `/api/folders/<id>` | S/K | any of `{name \| encName, parentId, starred}`. Moving a folder into itself or below itself → `400 "invalid move"`. |
| DELETE | `/api/folders/<id>` | S/K | deletes the folder **and everything inside** |
| POST | `/api/files` | S/K | **raw body** = the file. Headers: `X-Filename` (URL-encoded) or `X-Enc-Name`; `X-Folder: <id>`; `Content-Type` or `X-Enc-Mime`; for encrypted uploads also `X-Wrapped-Key` and `X-Plain-Size`. Up to `MAX_BODY_SIZE`. → the file record. `413` over quota. |
| GET | `/api/files` | S/K | all your files (flat) |
| GET | `/api/files/<id>` | S/K | download (attachment) |
| GET | `/api/files/<id>/content` | S/K | for previews: supports `Range`. Only safe types (images except SVG, audio, video, PDF, plain text) are served inline. Everything else is sent as a download with `CSP: sandbox`. |
| PATCH | `/api/files/<id>` | S/K | any of `{name \| encName, folderId, starred}` |
| DELETE | `/api/files/<id>` | S/K | delete |
| GET | `/api/search?q=&category=` | S/K | name search. `category` = images, videos, audio or docs. |
| GET | `/api/recent` | S/K | latest uploads |
| GET | `/api/starred` | S/K | starred files + folders |
| GET | `/api/usage` | S/K | `{used, files, quota}`. Bytes on disk; `quota` is `null` when unlimited. |

### Large files: resumable upload
| Method | Path | Auth | Body / notes |
|---|---|---|---|
| POST | `/api/uploads/init` | S/K | `{name \| encName, size?, folderId?, mime \| encMime, wrappedKey?, plainSize?}` → `{uploadId}`. Declaring `size` gets an early quota answer. |
| PUT | `/api/uploads/<uploadId>` | S/K | raw chunk, header `X-Offset: <bytes already sent>`. A wrong offset gets `409 {"error":"offset_mismatch","received":N}`: resume from `N`. Each chunk is checked against the quota, counting every unfinished upload. |
| GET | `/api/uploads/<uploadId>` | S/K | `{received, size, name}`: where to resume |
| POST | `/api/uploads/<uploadId>/complete` | S/K | turns it into a file → `{file}` |
| DELETE | `/api/uploads/<uploadId>` | S/K | abort and free the space. Uploads idle for 24 hours are removed automatically. |

## Notes (always end-to-end encrypted)
| Method | Path | Auth | Notes |
|---|---|---|---|
| GET | `/api/notes` | S/K | list |
| POST | `/api/notes` | S/K | `{encTitle, encBody}` → `{note}`. Plain `{title, body}` from old clients is still accepted; the web app encrypts those when they are next opened. |
| GET / PUT / DELETE | `/api/notes/<id>` | S/K | read / replace / delete |

## Storage requests
| Method | Path | Auth | Notes |
|---|---|---|---|
| POST | `/api/storage-requests` | S | `{uploadBytes, message?}`: the size of the upload that didn't fit. The server asks for usage + upload, rounded up to 100 MB. Replaces your pending request. `409` if unlimited or it already fits. |
| GET | `/api/storage-requests/mine` | S | your latest request and its status |

## Admin
| Method | Path | Auth | Notes |
|---|---|---|---|
| GET | `/api/admin/users` | A | every account: role, status, quota, usage |
| PATCH | `/api/admin/users/<id>` | A | any of `{role: "user"\|"admin", suspended: bool, storageQuotaBytes: int\|null}`. The last admin can't be demoted or suspended. |
| POST | `/api/admin/users/<id>/remove` | A | `{reason?}`: moves their data to `BACKUP_DIR`. The account stays and sees the removal notice. |
| POST | `/api/admin/users/<id>/restore` | A | brings removed data back |
| POST | `/api/admin/users/<id>/wipe` | A | `{confirmEmail}`: permanently deletes a removed account's backup |
| GET | `/api/admin/removed-users` | A | removed accounts |
| GET | `/api/admin/requests` | A | sign-ups waiting for approval |
| POST | `/api/admin/requests/<id>/approve` / `deny` | A | deny deletes the request |
| GET | `/api/admin/invites` | A | invite codes (used / unused / expired, who used them; never the code) |
| POST | `/api/admin/invites` | A | `{label?, expiresDays: 0-365}` (0 = never) → `{code:"CTT-XXXX-XXXX-XXXX"}`, **shown once** |
| DELETE | `/api/admin/invites/<id>` | A | revoke an unused code |
| GET | `/api/admin/storage-requests` | A | pending requests with current usage and the attempted upload |
| POST | `/api/admin/storage-requests/<id>/approve` | A | `{grantBytes?}`: defaults to what they asked for |
| POST | `/api/admin/storage-requests/<id>/deny` | A | |

## Live updates
`GET /api/events` (WebSocket, **S**, same-origin only, at most 10 per account and 200 total). The server pushes `{"type": "..."}` when something changes. The client then re-fetches that list (no data travels over the socket):

| Type | Sent to | Means |
|---|---|---|
| `files` | the owner | files or folders changed |
| `notes` | the owner | notes changed |
| `devices` | the owner | a device was added, approved or revoked |
| `me` | the owner | profile, picture or settings changed |
| `quota` | the owner | their storage limit or request changed |
| `account` | the owner | an admin changed their account (role, suspension, removal) |
| `requests`, `invites`, `users`, `storage` | admins | something to review on the Admin page |

## Examples with curl
```bash
B=https://localhost:8443; K="X-API-Key: csk_..."
curl -k -H "$K" $B/api/usage
curl -k -H "$K" -X POST $B/api/folders -d '{"parentId":0,"name":"Backups"}'
curl -k -H "$K" -H "X-Filename: report.pdf" -H "X-Folder: 1" --data-binary @report.pdf $B/api/files
curl -k -H "$K" "$B/api/fs?folder=1"
curl -k -H "$K" -o report.pdf $B/api/files/7
```
For anything beyond a quick test, use the `cloud` client ([COMPANION_APPS.md](COMPANION_APPS.md)): it handles chunking, resume, paths and certificate pinning.
