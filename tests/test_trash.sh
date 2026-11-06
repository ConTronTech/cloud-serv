#!/usr/bin/env bash
# Trash for real-folder accounts: list / restore / delete forever / empty.
source "$(dirname "$0")/lib.sh"
start_server 8133 || exit 1
U="http://$API"
T=$(tok_of "$(curl -s "$U/api/auth/register" -d '{"email":"tr@e.cc","password":"supersecret","inviteCode":"test-invite"}')")
TB=$(tok_of "$(curl -s "$U/api/auth/register" -d '{"email":"tb@e.cc","password":"supersecret","inviteCode":"test-invite"}')")
kill "$SRV_PID"; wait "$SRV_PID" 2>/dev/null
TR="$TESTDIR/tree/me"; mkdir -p "$TR"
printf 'TREE_ROOT=%s/tree\nTREE_SCAN_MINUTES=0\nTRASH_DAYS=30\n' "$TESTDIR" >> "$TESTDIR/config.env"
(cd "$ROOT" && ./cloud_serv admin set-tree --email tr@e.cc --dir me --config "$TESTDIR/config.env" >/dev/null)
launch_server || exit 1
TODAY=$(date +%Y-%m-%d)
mkf() { A -X POST "$U/api/folders" -d "{\"name\":\"$1\",\"parentId\":${2:-0}}" | grep -o '"id":[0-9]*' | head -1 | cut -d: -f2; }
up()  { A -X POST "$U/api/files" -H "X-Filename: $1" -H "X-Folder: ${2:-0}" --data-binary "$3" | grep -o '"id":[0-9]*' | head -1 | cut -d: -f2; }
tid() { A "$U/api/trash" | python3 -I -c "import json,sys;print(next((i['id'] for i in json.load(sys.stdin)['items'] if i['name']==sys.argv[1] and i['from']==sys.argv[2]),''))" "$1" "$2"; }

DOCS=$(mkf Docs); PRJ=$(mkf Project); SRC=$(mkf src "$PRJ")
NOTE=$(up note.txt "$DOCS" "hello"); up a.js "$SRC" "AAA" >/dev/null; up b.js "$SRC" "BBBB" >/dev/null

echo "== delete -> listed in trash =="
A -X DELETE "$U/api/files/$NOTE" >/dev/null
A -X DELETE "$U/api/folders/$PRJ" >/dev/null
L=$(A "$U/api/trash")
want "file listed" '"name":"note.txt"' "$L"
want "file shows where it came from" '"from":"Docs"' "$L"
want "folder listed" '"name":"Project"' "$L"
want "folder shows its file count" '"files":2' "$L"
want "folder shows its size" '"size":7' "$L"
want "purge date shown" "\"purgeOn\":\"" "$L"
printf '%s' "$L" | grep -q '"name":"Docs"' && bad "container folder listed as deleted" || ok "mirror folders (Docs) not listed as deleted items"

echo "== restore =="
R=$(A -X POST "$U/api/trash/restore" -d "{\"id\":\"$(tid note.txt Docs)\"}")
want "restore file" '"path":"Docs/note.txt"' "$R"
[ "$(cat "$TR/Docs/note.txt")" = hello ] && ok "file back on disk" || bad "file not back"
want "restored file listed again" '"name":"note.txt"' "$(A "$U/api/fs?folder=$DOCS")"
A "$U/api/trash" | grep -q '"name":"note.txt"' && bad "restored item still in trash" || ok "restored item gone from trash"
R=$(A -X POST "$U/api/trash/restore" -d "{\"id\":\"$(tid Project "")\"}")
want "restore folder with contents" '"files":2' "$R"
[ -f "$TR/Project/src/b.js" ] && ok "folder back with nested files" || bad "folder contents missing"
NP=$(A "$U/api/fs" | tr '}' '\n' | grep -F '"name":"Project"' | grep -o '"id":[0-9]*' | cut -d: -f2)
want "restored folder browsable" '"name":"src"' "$(A "$U/api/fs?folder=$NP")"

echo "== restore into a parent that was deleted too =="
SRC2=$(A "$U/api/fs?folder=$NP" | tr '}' '\n' | grep -F '"name":"src"' | grep -o '"id":[0-9]*' | cut -d: -f2)
A -X DELETE "$U/api/folders/$SRC2" >/dev/null       # Project/src
A -X DELETE "$U/api/folders/$NP" >/dev/null         # then Project itself
R=$(A -X POST "$U/api/trash/restore" -d "{\"id\":\"$(tid src Project)\"}")
want "restore src recreates Project" '"path":"Project/src"' "$R"
[ -f "$TR/Project/src/a.js" ] && ok "parent recreated on disk" || bad "parent not recreated"
want "recreated parent indexed" '"name":"Project"' "$(A "$U/api/fs")"
R=$(A -X POST "$U/api/trash/restore" -d "{\"id\":\"$(tid Project "")\"}")
want "restoring the old Project too lands as Project (1)" '"name":"Project (1)"' "$R"

echo "== same name deleted twice: both kept =="
X1=$(up dup.txt 0 "one"); A -X DELETE "$U/api/files/$X1" >/dev/null
X2=$(up dup.txt 0 "two"); A -X DELETE "$U/api/files/$X2" >/dev/null
[ "$(A "$U/api/trash" | grep -o '"name":"dup.txt"' | wc -l)" = 2 ] && ok "both dup.txt listed" || bad "dup.txt not listed twice"
[ -f "$TR/.trash/$TODAY/dup.txt" ] && [ -f "$TR/.trash/$TODAY/dup (1).txt" ] && ok "both kept on disk" || bad "a copy was lost"

echo "== delete forever / empty =="
ID=$(tid dup.txt "")
want "delete forever" '"ok":true' "$(A -X DELETE "$U/api/trash/item?id=$ID")"
[ "$(A "$U/api/trash" | grep -o '"name":"dup.txt"' | wc -l)" = 1 ] && ok "one dup.txt left" || bad "wrong item deleted"
want "unknown id" "not in the trash" "$(A -X DELETE "$U/api/trash/item?id=$TODAY:999")"
want "path-ish id refused" "not in the trash" "$(A -X DELETE "$U/api/trash/item?id=../../x:0")"
want "empty trash" '"ok":true' "$(A -X DELETE "$U/api/trash")"
want "trash empty" '"items":[]' "$(A "$U/api/trash")"
[ -z "$(ls -A "$TR/.trash" 2>/dev/null)" ] && ok "nothing left in .trash" || bad ".trash not empty: $(ls -A "$TR/.trash")"
[ -f "$TR/Docs/note.txt" ] && [ -f "$TR/Project/src/a.js" ] && ok "live files untouched by empty" || bad "empty touched live files"

echo "== blob accounts =="
T=$TB
want "blob account has no trash" "no trash" "$(A "$U/api/trash")"

finish
