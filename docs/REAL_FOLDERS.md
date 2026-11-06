# Real-folder storage ("tree mode")

Status: implemented 2026-11-05 (tests: `tests/test_tree.sh`, 68 checks, clean under ASan/UBSan). Goal: an unencrypted account's files live on disk as a normal folder tree,
so `/mnt/storage/Cloud/contolis/` *is* the account and survives without the database.

## Modes (per account)
| | `blob` (today, default) | `tree` (new) |
|---|---|---|
| On disk | `STORAGE_DIR/<user_id>/<hex key>` | `TREE_ROOT/<dir>/<folder path>/<name>` |
| Names/folders live in | SQLite only | the filesystem (SQLite is an index of it) |
| E2E encryption | allowed | **not allowed** (names must be visible on disk) |
| Lose the DB | files unusable | nothing lost, rescan rebuilds the index |

`users.storage_mode` ('blob' | 'tree'). Switching an account with existing files = admin-only
conversion step (later). New config: `TREE_ROOT=` (empty = feature off).

## The database becomes an index
Keep the `files` / `folders` tables and their ids, so every route, the web app, live events, stars,
recent and search keep working unchanged. For tree accounts:
- a row's disk path = account root + folder chain + name (computed, nothing stored);
- `storage_key` holds `-` (unused); `stored_size` = real size on disk.

## Every operation maps to the filesystem
| App action | Disk action |
|---|---|
| create folder | `mkdirat` |
| upload | write to `<root>/.cloud-serv/uploads/<session>` (same filesystem), then `renameat` into place on complete: atomic, never a half file in the tree |
| rename / move file or folder | `renameat` (instant, any size) |
| delete | move into `<root>/.trash/<date>/<original path>`; purged after `TRASH_DAYS` (default 30, 0 = delete straight away) |
| download / preview / zip | open the real path |
| name clash in a folder | refused (409), same as a real filesystem |

Disk first, DB second: if the disk step fails, the DB is untouched. If the DB step fails after the disk step,
the next scan repairs it.

## Scanner (disk → DB)
- Full scan at startup, every `TREE_SCAN_MINUTES` (default 15), and on demand (`cloudctl rescan`).
- Adds rows for new files/folders, removes rows for vanished ones, updates sizes/mtimes. Keeps stars
  and ids of anything still present (matched by path, then by inode for renames done outside the app).
- Live changes go out over the existing WebSocket events.
- Later: inotify for instant pickup (needs care with ~hundreds of thousands of dirs).
- Skips `.cloud-serv/` and `.trash/`.

## Safety (path traversal was cpp-server's worst bug)
- Every access walks from an open fd of the account root with `openat(..., O_NOFOLLOW)` one component
  at a time. No string-built absolute paths reach `open()`.
- Names: no `/`, no NUL, not `.` / `..`, no leading `.cloud-serv` / `.trash`, max 255 bytes.
- Symlinks inside the tree are listed as nothing (ignored by the scanner, never followed).
- Names from disk that break these rules (non-UTF-8, control chars, reserved) are skipped by the scan,
  reported (`cloudctl rescan` / log), and left untouched on disk.
- The account root is the CT's mount; nothing outside it is reachable even with a bug in path code.

## Tests (tests/test_tree.sh)
traversal (`..`, encoded, symlink planted in the tree, symlinked parent), name clashes, rename/move of
deep folders, delete → trash → purge, files added/removed/renamed behind the app's back, upload
interrupted mid-way, non-UTF-8 and very long names, 0-byte and >5 GB files (adopted), a scan of a
copy of `cloud-serv-testfiles`.

## Using it
```bash
# config.env:  TREE_ROOT=/srv/cloud   (TRASH_DAYS=30, TREE_SCAN_MINUTES=15 are the defaults)
cloudctl tree you@example.com contolis   # account must be empty; existing files in /srv/cloud/contolis are indexed
cloudctl rescan                          # after copying files in by hand (running server: SIGHUP)
```
- `cloudctl backup` does not copy real-folder trees (they live outside the data dir): back the tree up
  separately. The database is only an index, so a restore + rescan rebuilds it.
- Admin "remove"/"wipe" of a tree account deletes its index and account, never the folder on disk.
  A removed account is not scanned; "restore" brings the index back (the files never left).
- Files added outside the app keep their mtime as the "added" date, so Recent isn't flooded by an import.
- Stars/ids survive a rescan for anything still at the same path. A rename done outside the app looks
  like delete + add (the star is lost); renames done in the app keep everything.

## Scale (measured)
- 1,000,000 files / 10k folders: first import 5 s, rescan 2.5 s, **peak ~180 MB** (walk keeps a parent
  index per entry; sync matches folders by (parent, name) and files by sort-merge; `malloc_trim` after).
- Production (CT 130, USB SSD): 862,634 files / 113,243 folders indexed in 12 s.

## Not done yet
- inotify (instant pickup); today it's startup + every TREE_SCAN_MINUTES + SIGHUP.
- Converting an account that already has blob files (set-tree refuses non-empty accounts).
- Web UI: the encryption toggle is refused by the server (409) but not hidden yet (`/api/auth/me` returns
  `storageMode` for that).
