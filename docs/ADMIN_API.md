# Admin API

Account management for the operator. Every route requires a **login session**
(cookie or `Authorization: Bearer <session token>`; an API key is rejected, same
rule as API-key management) **and** `role = admin`. `401` = not signed in,
`403 {"error":"admin only"}` = signed in but not an admin.

## The boundary this API keeps

It manages **accounts**: who can log in, their role, their storage allowance, and
whether the account exists. It has **no route that lists, reads, or restores a
user's files or folders**, and there is nothing to add one to: contents, names and
mime types are end-to-end encrypted and the server never holds a key.

Two honest limits:
- **Notes are not end-to-end encrypted.** Titles and bodies are plaintext in the
  database, so whoever controls the server's disk can read them, and a `remove`
  backup contains them. The admin *API* never exposes them; the disk does.
- Sizes, counts, timestamps and folder structure are visible to the server (see
  `SECURITY.md`). The user listing shows sizes and counts, never names.

## Bootstrap

The lowest-id account is promoted to `admin` automatically if no admin exists
(fresh database or upgrade). New registrations are plain `user`s. New accounts get
`DEFAULT_STORAGE_QUOTA_GB` (0 = unlimited).

## Read

`GET /api/admin/users`
```json
{"users":[{"id":2,"email":"u@e.cc","displayName":"u","createdAt":"…","role":"user",
           "status":"active","storageUsedBytes":1048576,"storageQuotaBytes":null,"fileCount":3}]}
```

`GET /api/admin/removed-users`
```json
{"removedUsers":[{"id":3,"originalUserId":7,"email":"x@e.cc","displayName":"x",
                  "removedAt":"…","removedBy":1}]}
```
(No filesystem path is ever returned.)

## Change an account

`PATCH /api/admin/users/<id>` — any subset of:
```json
{"role":"user|admin", "suspended":true, "storageQuotaBytes":5368709120}
```
`storageQuotaBytes: null` = unlimited. Returns the updated user. `409` if the change
would leave zero admins. **Suspend** takes effect on the very next request: the
account's sessions and API keys stop authenticating and login answers
`403 account suspended` (only after a correct password, so it can't probe status).
Nothing is deleted; un-suspend restores access.

## Remove and wipe

| Action | Route | Reversible? |
|---|---|---|
| **Suspend** | `PATCH …/users/<id>` `{"suspended":true}` | Yes, instantly |
| **Backup + remove** | `POST /api/admin/users/<id>/remove` | The backup exists on disk; **there is no restore endpoint** |
| **Wipe a live account** | `POST /api/admin/users/<id>/wipe` `{"confirmEmail":"…"}` | **No.** No backup is made |
| **Wipe a removed account** | `POST /api/admin/removed-users/<id>/wipe` `{"confirmEmail":"…"}` | **No.** Deletes the backup |

All four refuse: an unknown id (`404`), **your own account** (`409`), and the last
admin (`409`). Both wipes additionally require `confirmEmail` to equal the
account's email (case-insensitive) or they answer `400` and change nothing.

### What `remove` does

Everything happens under one exclusive database lock, so nothing can slip in
between the snapshot and the delete:

1. Snapshot the account's rows (user, folders, files, notes) to
   `BACKUP_DIR/<id>_<utc>/data.json` (dir `0700`, file `0600`).
2. Put the account's still-encrypted blobs in `BACKUP_DIR/<id>_<utc>/storage/`
   (hard links when the filesystem allows, so no extra disk; a real copy otherwise).
3. In **one transaction**: record a `removed_users` tombstone and delete the user
   (cascading sessions, API keys, folders, files, notes, upload sessions).
4. Only after the commit, delete the live blob directory.

If any step fails, the transaction is rolled back and the partial backup is
deleted: the live account is left exactly as it was. Response:
`{"removedUserId":7,"tombstoneId":3,"storageRemoved":true}`.

User ids are never reused, so a removed account's id can never inherit its old
storage; the same email can re-register and gets a new id.

### What `wipe` does

Deletes the account's rows in one transaction, then its blob directory (or, for a
removed account, its whole backup folder and tombstone). The recursive delete of a
backup only ever targets a **direct child of `BACKUP_DIR`**; a tampered tombstone
pointing anywhere else is refused.

## Configuration

| Key | Default | Meaning |
|---|---|---|
| `DEFAULT_STORAGE_QUOTA_GB` | `0` | Quota for new registrations (0 = unlimited) |
| `BACKUP_DIR` | `data/backups` | Where `remove` writes backups |

## Not built (yet)

- **Restore** of a removed account from its backup.
- Secure shredding: wipe deletes files normally. The data is ciphertext, but the
  bytes are not overwritten.
- Backups of `sessions`/`api_keys`/in-progress uploads (intentionally excluded).
