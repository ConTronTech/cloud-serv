#!/usr/bin/env bash
# Real-folder ("tree") storage: docs/REAL_FOLDERS.md
source "$(dirname "$0")/lib.sh"
start_server 8131 || exit 1

U="http://$API"
TOK=$(tok_of "$(curl -s "$U/api/auth/register" -d '{"email":"tree@e.cc","password":"supersecret","inviteCode":"test-invite"}')")
T2=$(tok_of "$(curl -s "$U/api/auth/register" -d '{"email":"blob@e.cc","password":"supersecret","inviteCode":"test-invite"}')")
T=$TOK

# ---- prepare a tree with existing content, then switch the account to it (server stopped) ----
kill "$SRV_PID"; wait "$SRV_PID" 2>/dev/null
ROOTDIR="$TESTDIR/tree"; TR="$ROOTDIR/me"; OUT="$TESTDIR/outside"
mkdir -p "$TR/Docs" "$TR/Media/Sub" "$TR/Empty" "$OUT"
printf 'hello tree' > "$TR/Docs/a.txt"
head -c 300000 /dev/urandom > "$TR/Media/Sub/v.mp4"
printf 'TOPSECRET' > "$OUT/secret.txt"
ln -s /etc "$TR/evil-dir"                     # symlinked dir: never indexed or followed
ln -s /etc/passwd "$TR/Docs/passwd-link"      # symlinked file
touch "$TR/Docs/$(printf 'bad\nname')"        # control char in name
touch "$TR/Docs/$(printf 'latin1-\xe9')"      # not UTF-8
mkdir -p "$TR/.trash/2000-01-01" && touch "$TR/.trash/2000-01-01/old" "$TR/.trash/keep-me"
cat >> "$TESTDIR/config.env" <<EOF
TREE_ROOT=$ROOTDIR
TRASH_DAYS=30
TREE_SCAN_MINUTES=0
EOF

echo "== set-tree (CLI) =="
OUTP=$(cd "$ROOT" && ./cloud_serv admin set-tree --email tree@e.cc --dir me --config "$TESTDIR/config.env" 2>&1)
want "set-tree switches the account" "now uses real folders" "$OUTP"
want "existing files indexed" "+2 files" "$OUTP"
want "existing folders indexed (Docs, Media, Media/Sub, Empty)" "+4 folders" "$OUTP"
want "symlinks reported, not indexed" "(symlink)" "$OUTP"
want "bad names reported, not indexed" "(name not allowed)" "$OUTP"
want "old trash purged" "trash purged 1" "$OUTP"
[ ! -e "$TR/.trash/2000-01-01" ] && ok "dated trash folder older than 30 days removed" || bad "old trash kept"
[ -e "$TR/.trash/keep-me" ] && ok "unknown things in .trash left alone" || bad "purge removed a non-dated entry"
want "set-tree refuses a second dir" "already uses real folders" "$(cd "$ROOT" && ./cloud_serv admin set-tree --email tree@e.cc --dir other --config "$TESTDIR/config.env" 2>&1)"
want "set-tree refuses traversal dir" "--dir must be" "$(cd "$ROOT" && ./cloud_serv admin set-tree --email blob@e.cc --dir ../x --config "$TESTDIR/config.env" 2>&1)"
want "rescan of a blob account refused" "does not use real folders" "$(cd "$ROOT" && ./cloud_serv admin rescan --email blob@e.cc --config "$TESTDIR/config.env" 2>&1)"
launch_server || exit 1

fid() { A "$U/api/fs${1:+?folder=$1}" | tr '}' '\n' | grep -F "\"name\":\"$2\"" | grep -o '"id":[0-9]*' | head -1 | cut -d: -f2; }
DOCS=$(fid "" Docs); MEDIA=$(fid "" Media)

echo "== listing + reading existing files =="
ROOTLS=$(A "$U/api/fs")
want "root lists Docs" '"name":"Docs"' "$ROOTLS"
want "root lists Empty" '"name":"Empty"' "$ROOTLS"
printf '%s' "$ROOTLS" | grep -q 'evil-dir' && bad "symlinked dir listed" || ok "symlinked dir not listed"
printf '%s' "$ROOTLS" | grep -qE '\.trash|\.cloud-serv' && bad "reserved dir listed" || ok "reserved dirs hidden"
A_ID=$(fid "$DOCS" a.txt)
want "download existing file" "hello tree" "$(A "$U/api/files/$A_ID")"
want "Range read" "tree" "$(A -H 'Range: bytes=6-9' "$U/api/files/$A_ID/content")"
want "mime guessed from extension" '"mime":"video/mp4"' "$(A "$U/api/fs?folder=$(fid "$MEDIA" Sub)")"
want "/me reports tree mode" '"storageMode":"tree"' "$(A "$U/api/auth/me")"
want "encryption can't be enabled" "not available for real-folder" "$(A -X PATCH "$U/api/auth/me/prefs" -d '{"encryptFiles":true}')"

echo "== uploads land as real files =="
R=$(A -X POST "$U/api/files" -H "X-Filename: new.txt" -H "X-Folder: $DOCS" --data-binary "NEW")
want "upload ok" '"name":"new.txt"' "$R"
[ "$(cat "$TR/Docs/new.txt" 2>/dev/null)" = NEW ] && ok "bytes at Docs/new.txt on disk" || bad "file not on disk"
want "same name auto-renamed" '"name":"new (1).txt"' "$(A -X POST "$U/api/files" -H "X-Filename: new.txt" -H "X-Folder: $DOCS" --data-binary "TWO")"
[ -f "$TR/Docs/new (1).txt" ] && ok "renamed copy on disk" || bad "renamed copy missing"
want "encrypted upload refused" "not available for real-folder" "$(A -X POST "$U/api/files" -H "X-Enc-Name: QUJD.REVG" -H "X-Folder: 0" --data-binary "x")"
want "reserved name .trash refused" "invalid filename" "$(A -X POST "$U/api/files" -H "X-Filename: .trash" --data-binary "x")"
want "slash in name refused" "invalid filename" "$(A -X POST "$U/api/files" -H "X-Filename: a%2Fb" --data-binary "x")"
want "dotdot refused" "invalid filename" "$(A -X POST "$U/api/files" -H "X-Filename: .." --data-binary "x")"
[ ! -e "$ROOTDIR/x" ] && [ ! -e "$TR/a" ] && ok "nothing written outside the account" || bad "stray file written"

echo "== chunked upload =="
UP=$(A -X POST "$U/api/uploads/init" -d "{\"name\":\"big.bin\",\"size\":6,\"folderId\":$MEDIA}")
UID_=$(printf '%s' "$UP" | grep -o '"uploadId":"[^"]*"' | cut -d'"' -f4)
A -X PUT "$U/api/uploads/$UID_" -H "X-Offset: 0" --data-binary "abc" >/dev/null
A -X PUT "$U/api/uploads/$UID_" -H "X-Offset: 3" --data-binary "def" >/dev/null
[ ! -e "$TR/Media/big.bin" ] && ok "partial upload not visible in the tree" || bad "half file visible"
want "complete" '"name":"big.bin"' "$(A -X POST "$U/api/uploads/$UID_/complete")"
[ "$(cat "$TR/Media/big.bin" 2>/dev/null)" = abcdef ] && ok "chunked file assembled on disk" || bad "chunked file wrong"
UP2=$(A -X POST "$U/api/uploads/init" -d '{"name":"gone.bin","size":3,"folderId":0}')
U2=$(printf '%s' "$UP2" | grep -o '"uploadId":"[^"]*"' | cut -d'"' -f4)
A -X PUT "$U/api/uploads/$U2" -H "X-Offset: 0" --data-binary "zz" >/dev/null
A -X DELETE "$U/api/uploads/$U2" >/dev/null
[ -z "$(ls -A "$TR/.cloud-serv/uploads" 2>/dev/null)" ] && ok "temp space empty after complete + abort" || bad "temp leftovers: $(ls "$TR/.cloud-serv/uploads")"
want "encrypted chunked upload refused" "not available for real-folder" "$(A -X POST "$U/api/uploads/init" -d '{"encName":"QUJD.REVG","size":1}')"

echo "== folders =="
NF=$(A -X POST "$U/api/folders" -d '{"name":"Projects"}'); PJ=$(id_of "$NF")
[ -d "$TR/Projects" ] && ok "folder created on disk" || bad "folder missing on disk"
want "duplicate folder refused" "already exists" "$(A -X POST "$U/api/folders" -d '{"name":"Projects"}')"
want "reserved folder name refused" "invalid folder name" "$(A -X POST "$U/api/folders" -d '{"name":".cloud-serv"}')"
SUBF=$(id_of "$(A -X POST "$U/api/folders" -d "{\"name\":\"Inner\",\"parentId\":$PJ}")")
want "rename folder" '"name":"Work"' "$(A -X PATCH "$U/api/folders/$PJ" -d '{"name":"Work"}')"
[ -d "$TR/Work/Inner" ] && [ ! -e "$TR/Projects" ] && ok "folder renamed on disk with contents" || bad "folder rename not on disk"
want "move folder into own subfolder refused" "invalid move" "$(A -X PATCH "$U/api/folders/$PJ" -d "{\"parentId\":$SUBF}")"
[ -d "$TR/Work/Inner" ] && ok "tree unchanged after refused move" || bad "tree damaged by refused move"
A -X PATCH "$U/api/folders/$PJ" -d "{\"parentId\":$DOCS}" >/dev/null
[ -d "$TR/Docs/Work/Inner" ] && ok "folder moved on disk" || bad "folder move not on disk"
want "rename into an existing name refused" "already exists" "$(A -X PATCH "$U/api/folders/$PJ" -d '{"name":"new.txt"}')"

echo "== files: rename / move / star =="
NEWID=$(fid "$DOCS" new.txt)
A -X PATCH "$U/api/files/$NEWID" -d '{"name":"renamed.txt"}' >/dev/null
[ -f "$TR/Docs/renamed.txt" ] && [ ! -e "$TR/Docs/new.txt" ] && ok "file renamed on disk" || bad "file rename not on disk"
want "rename onto existing file refused" "already exists" "$(A -X PATCH "$U/api/files/$NEWID" -d '{"name":"a.txt"}')"
A -X PATCH "$U/api/files/$NEWID" -d "{\"folderId\":$MEDIA}" >/dev/null
[ -f "$TR/Media/renamed.txt" ] && ok "file moved on disk" || bad "file move not on disk"
A -X PATCH "$U/api/files/$A_ID" -d '{"starred":true}' >/dev/null

echo "== delete goes to .trash =="
TODAY=$(date +%Y-%m-%d)
A -X DELETE "$U/api/files/$NEWID" >/dev/null
[ ! -e "$TR/Media/renamed.txt" ] && [ -f "$TR/.trash/$TODAY/Media/renamed.txt" ] && ok "deleted file kept in trash" || bad "file not in trash"
A -X DELETE "$U/api/folders/$PJ" >/dev/null
[ ! -e "$TR/Docs/Work" ] && [ -d "$TR/.trash/$TODAY/Docs/Work/Inner" ] && ok "deleted folder kept in trash" || bad "folder not in trash"

echo "== changes made outside the app =="
hup_until() {  # hup_until <grep pattern> <url> <present|absent>
  local i; kill -HUP "$SRV_PID"
  for i in $(seq 1 40); do
    if A "$2" | grep -q "$1"; then [ "$3" = present ] && return 0; else [ "$3" = absent ] && return 0; fi
    sleep 0.25
  done; return 1
}
printf 'dropped' > "$TR/Docs/dropped.txt"; mkdir -p "$TR/Docs/NewDir/Deep"; printf x > "$TR/Docs/NewDir/Deep/d.txt"
hup_until '"name":"dropped.txt"' "$U/api/fs?folder=$DOCS" present && ok "file added on disk appears after rescan" || bad "added file not indexed"
want "nested dir added on disk indexed" '"name":"NewDir"' "$(A "$U/api/fs?folder=$DOCS")"
want "star survives rescan" '"starred":true' "$(A "$U/api/starred")"
DROP=$(fid "$DOCS" dropped.txt)
rm "$TR/Docs/dropped.txt"
want "file removed on disk -> 404 before the rescan" "not found" "$(A "$U/api/files/$DROP")"
hup_until '"name":"dropped.txt"' "$U/api/fs?folder=$DOCS" absent && ok "file removed on disk disappears after rescan" || bad "removed file still listed"
printf 'grown' >> "$TR/Docs/a.txt"
hup_until '"size":15' "$U/api/fs?folder=$DOCS" present && ok "size change picked up" || bad "size not updated"

echo "== symlink swap (traversal) =="
mkdir -p "$TR/Swap"; printf 'mine' > "$TR/Swap/secret.txt"
hup_until '"name":"Swap"' "$U/api/fs" present >/dev/null
SW=$(fid "" Swap); SEC=$(fid "$SW" secret.txt)
want "indexed file readable" "mine" "$(A "$U/api/files/$SEC")"
mv "$TR/Swap" "$TR/Swap.real"; ln -s "$OUT" "$TR/Swap"           # folder swapped for a symlink outside
R=$(A "$U/api/files/$SEC"); printf '%s' "$R" | grep -q TOPSECRET && bad "followed a swapped-in symlink!" || ok "swapped-in folder symlink not followed (download)"
R=$(A "$U/api/files/$SEC/content"); printf '%s' "$R" | grep -q TOPSECRET && bad "content route followed symlink!" || ok "swapped-in folder symlink not followed (content)"
R=$(A -H 'Range: bytes=0-3' "$U/api/files/$SEC/content"); printf '%s' "$R" | grep -q TOPS && bad "range route followed symlink!" || ok "swapped-in folder symlink not followed (range)"
rm "$TR/Swap"; mv "$TR/Swap.real" "$TR/Swap"; rm "$TR/Swap/secret.txt"; ln -s "$OUT/secret.txt" "$TR/Swap/secret.txt"
R=$(A "$U/api/files/$SEC"); printf '%s' "$R" | grep -q TOPSECRET && bad "followed a file symlink!" || ok "swapped-in file symlink not followed"
rm -rf "$TR/Swap"; ln -s "$OUT" "$TR/Swap"
want "upload into a symlinked folder refused" "error" "$(A -X POST "$U/api/files" -H "X-Filename: plant.txt" -H "X-Folder: $SW" --data-binary "P")"
[ ! -e "$OUT/plant.txt" ] && ok "nothing written through the symlink" || bad "wrote through a symlink!"
want "mkdir inside a symlinked folder refused" "error" "$(A -X POST "$U/api/folders" -d "{\"name\":\"z\",\"parentId\":$SW}")"
[ ! -e "$OUT/z" ] && ok "no folder created through the symlink" || bad "mkdir through a symlink!"
A -X PATCH "$U/api/files/$A_ID" -d "{\"folderId\":$SW}" >/dev/null
[ ! -e "$OUT/a.txt" ] && ok "no move through the symlink" || bad "moved through a symlink!"

echo "== blob accounts are untouched =="
T=$T2
R=$(A -X POST "$U/api/files" -H "X-Filename: blob.txt" --data-binary "BLOB")
want "blob upload ok" '"name":"blob.txt"' "$R"
[ -n "$(ls "$TESTDIR/storage"/*/ 2>/dev/null)" ] && ok "blob account still uses hex storage" || bad "blob storage empty"
[ ! -e "$ROOTDIR/blob.txt" ] && ok "blob account wrote nothing to the tree" || bad "blob file in tree"
want "/me reports blob mode" '"storageMode":"blob"' "$(A "$U/api/auth/me")"

echo "== admin remove / restore of a tree account =="
dbq() { python3 -c "import sqlite3,sys; c=sqlite3.connect('$TESTDIR/cloud.db'); r=c.execute(sys.argv[1]).fetchone(); c.commit(); print(r[0] if r else '')" "$1"; }
dbq "UPDATE users SET role='admin' WHERE email='blob@e.cc'" >/dev/null
TID=$(dbq "SELECT id FROM users WHERE email='tree@e.cc'")
BEFORE=$(find "$TR" -type f | wc -l)
want "remove tree account" '"status":"removed"' "$(A -X POST "$U/api/admin/users/$TID/remove")"
[ "$(find "$TR" -type f | wc -l)" = "$BEFORE" ] && ok "removal left every file on disk ($BEFORE)" || bad "removal touched the tree"
kill -HUP "$SRV_PID"; sleep 1.5
[ "$(dbq "SELECT COUNT(*) FROM files WHERE user_id=$TID")" = 0 ] && ok "scanner skips a removed account" || bad "scanner re-indexed a removed account"
want "restore tree account" '"status":"active"' "$(A -X POST "$U/api/admin/users/$TID/restore")"
T=$(tok_of "$(curl -s "$U/api/auth/login" -d '{"email":"tree@e.cc","password":"supersecret"}')")
want "restored account lists its folders again" '"name":"Docs"' "$(A "$U/api/fs")"
want "restored account reads its files" "hello treegrown" "$(A "$U/api/files/$A_ID")"

echo "== deleting a big folder is fast (indexed recursive delete) =="
python3 -I -c "
import os,sys
r=sys.argv[1]
for i in range(8000): os.makedirs(f'{r}/Other/o{i//100}/d{i}', exist_ok=True)
for i in range(2000): os.makedirs(f'{r}/Huge/h{i//50}/d{i}', exist_ok=True)
for i in range(0,2000,10): open(f'{r}/Huge/h{i//50}/d{i}/f.txt','w').write('x')
" "$TR"
hup_until '"name":"Huge"' "$U/api/fs" present >/dev/null
HUGE=$(fid "" Huge)
S=$(date +%s%N); R=$(A -X DELETE "$U/api/folders/$HUGE"); E=$(( ($(date +%s%N) - S) / 1000000 ))
want "big folder delete ok" '"ok":true' "$R"
[ "$E" -lt 1500 ] && ok "2,000-folder delete next to 8,000 others took ${E} ms (< 1.5 s)" || bad "big folder delete took ${E} ms"
[ -d "$TR/.trash/$(date +%Y-%m-%d)/Huge/h0/d0" ] && ok "big folder went to trash intact" || bad "big folder not in trash"
want "other folders untouched" '"name":"Other"' "$(A "$U/api/fs")"
U1=$(A "$U/api/usage"); A -X POST "$U/api/files" -H "X-Filename: cache-test.txt" --data-binary "12345" >/dev/null
U2=$(A "$U/api/usage")
[ "$U1" != "$U2" ] && ok "usage cache refreshes after an upload ($U1 -> $U2)" || bad "usage cache stale after upload"

echo "== clean shutdown with the scanner running =="
kill -HUP "$SRV_PID"; kill -TERM "$SRV_PID"; wait "$SRV_PID"; RC=$?; SRV_PID=""
[ "$RC" = 0 ] && ok "server exits 0 on SIGTERM" || bad "server exit code $RC"
tail -5 "$TESTDIR/server.log" | grep -q "cannot open account dir" && bad "scanner ran after shutdown (use-after-free)" || ok "scanner stopped before shutdown"

finish
