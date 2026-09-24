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
- **Legacy plaintext notes.** Notes are now end-to-end encrypted (title and body), but a note
  written before that change stays plaintext in the database until its owner next opens the Notes
  tab, when the browser upgrades it in place. Until then the server (and so a `remove` backup) can
  read it. The admin *API* never exposes note content either way.
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

`GET /api/admin/removed-users` — accounts whose data was removed (newest first)
```json
{"removedUsers":[{"id":1,"originalUserId":7,"email":"x@e.cc","displayName":"x",
                  "removedAt":"…","removedBy":1,"reason":"Reported for abuse","backupBytes":1979}]}
```
`backupBytes` is the backup's size on disk (data.json + blobs). No filesystem path is ever returned.

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

## Suspend, remove, restore, wipe

Four things an admin can do to an account, from mild to permanent:

| Action | Route | Effect | Reversible? |
|---|---|---|---|
| **Suspend** | `PATCH …/users/<id>` `{"suspended":true}` | Blocks sign-in and kills sessions/API keys. Nothing is deleted | Yes, instantly |
| **Remove data** | `POST …/users/<id>/remove` `{"reason"?}` | Backs up the account's data and takes it away. **The account stays** | **Yes: restore** |
| **Restore** | `POST …/users/<id>/restore` | Puts the data back exactly as it was | — |
| **Wipe** | `POST …/users/<id>/wipe` `{"confirmEmail"}` | Permanently deletes the account, its data and any backup | **No** |

`remove`, `restore` and `wipe` all refuse an unknown id (`404`), **your own account** (`409`)
and the **last active admin** (`409`). `wipe` additionally requires `confirmEmail` to equal the
account's email (case-insensitive), otherwise `400` and nothing changes.

"Last admin" counts only admins who can act (role `admin` **and** status `active`). A suspended
or removed admin does not count, so you cannot demote or remove the only admin who is still able
to sign in.

### What a removed account looks like

The account is **not** deleted. Its status becomes `removed`; its password, recovery key and
encryption key material are kept, and so are its API keys (inert until restore). Only its
folders, files, notes and sessions are taken away. So:

- **Signing in** with the correct password returns `403` with no session, and a body the client
  can show:
  ```json
  {"error":"account data removed","code":"data_removed",
   "notice":"Your data has been temporarily removed. To get it back, please appeal.",
   "reason":"Reported for abuse","appealContact":"appeals@example.com"}
  ```
  A wrong password still answers `401 invalid credentials`, so this can't be used to probe
  account status. (A suspended account answers `403 {"code":"suspended"}`.)
- The web client shows that text on the login screen.
- The suspend toggle cannot touch a removed account (`409`): it leaves that state only through
  **restore** or **wipe**.
- Removing an already-removed account is a `409`.

`reason` (optional, max 500 chars, no control characters) is shown to the account's owner.
`REMOVED_ACCOUNT_NOTICE` and `APPEAL_CONTACT` (see Configuration) control the rest of the text.

### What `remove` does

Everything happens under one exclusive database lock, so nothing can slip in between the
snapshot and the delete:

1. Snapshot the account's folders, files and notes to `BACKUP_DIR/<id>_<utc>/data.json`
   (dir `0700`, file `0600`).
2. Put its still-encrypted blobs in `BACKUP_DIR/<id>_<utc>/storage/` (hard links when the
   filesystem allows, so no extra disk; a real copy otherwise).
3. In **one transaction**: record the removal, mark the account `removed`, and delete its
   folders/files/notes/upload sessions/sessions.
4. Only after the commit, delete the live blob directory.

If any step fails the transaction is rolled back and the partial backup is deleted: the account
is left exactly as it was. Response: `{"removedUserId":7,"status":"removed","storageRemoved":true}`.

### What `restore` does

1. Validates the backup **before touching anything**: it must be a direct child of `BACKUP_DIR`,
   `data.json` must parse and belong to *this* account, every storage key must be plain hex, and
   every file row's blob must exist in the bundle (an incomplete backup is refused).
2. Puts the blobs back **first** (so a row can never point at a missing blob).
3. In **one transaction**: re-inserts the folders, files and notes with their **original ids**
   (so the folder tree and every reference is identical), sets the account `active` and deletes
   the removal record. Only columns that exist in the live table are written, so a tampered
   `data.json` cannot smuggle SQL through a key name.
4. Deletes the backup (it has been consumed).

If anything fails, the transaction is rolled back, the blobs it placed are removed again, and the
backup is left intact for another try. Response:
`{"restoredUserId":7,"status":"active","folders":1,"files":2,"notes":2}`.

The owner can then sign in and their own key unlocks everything, because their key material was
never removed. A restored account is `active` (even if it was suspended before it was removed).

### What `wipe` does

Deletes the account's rows in one transaction, then its blob directory. For an already-removed
account it also deletes its whole backup bundle. That recursive delete only ever targets a
**direct child of `BACKUP_DIR`**, and the path is vetted *before* the transaction, so a tampered
record pointing anywhere else makes the whole wipe refuse (`500`) with nothing changed. Response:
`{"wiped":true,"storageRemoved":true,"backupRemoved":true}`.

User ids are never reused, so a wiped or removed account's id can never inherit its old storage.

## Configuration

| Key | Default | Meaning |
|---|---|---|
| `DEFAULT_STORAGE_QUOTA_GB` | `0` | Quota for new registrations (0 = unlimited) |
| `BACKUP_DIR` | `data/backups` | Where `remove` writes backups |
| `REMOVED_ACCOUNT_NOTICE` | "Your data has been temporarily removed. To get it back, please appeal." | Shown at sign-in to a removed account |
| `APPEAL_CONTACT` | *(empty)* | Address/URL shown with the notice so people know where to appeal |

## Not built (yet)

- **In-app appeals.** The notice tells people to appeal and shows `APPEAL_CONTACT`, but there is
  no form: appeals happen outside the app (email etc.).
- Secure shredding: wipe deletes files normally. The data is ciphertext, but the bytes are not
  overwritten.
- Backups of `sessions` and in-progress uploads (intentionally excluded); a restored account's
  users simply sign in again.
