#!/usr/bin/env bash
source "$(dirname "$0")/lib.sh"
start_server 8093 || exit 1
T=$(tok_of "$(curl -s "http://$API/api/auth/register" -d '{"email":"d@e.cc","password":"supersecret","inviteCode":"test-invite"}')")
fid_in(){ A "$1" | tr '}' '\n' | grep -F "\"name\":\"$2\"" | grep -o '"id":[0-9]*' | head -1 | cut -d: -f2; }

echo "== create tree + navigation =="
PH=$(A -X POST "http://$API/api/folders" -d '{"name":"Photos"}'); PID=$(id_of "$PH")
want "create Photos" '"name":"Photos"' "$PH"
SUB=$(A -X POST "http://$API/api/folders" -d "{\"name\":\"2026\",\"parentId\":$PID}"); SID=$(id_of "$SUB")
want "create Photos/2026" '"parentId":'"$PID" "$SUB"
want "bad folder name rejected" "invalid folder name" "$(A -X POST "http://$API/api/folders" -d '{"name":"a/b"}')"
A -X POST "http://$API/api/files" -H "X-Filename: pic.jpg" -H "X-Folder: $PID" --data-binary "JPG" >/dev/null
want "fs root shows Photos" '"name":"Photos"' "$(A "http://$API/api/fs")"
want "fs Photos shows 2026" '"name":"2026"' "$(A "http://$API/api/fs?folder=$PID")"
want "fs Photos breadcrumb" '"name":"Photos"' "$(A "http://$API/api/fs?folder=$PID")"

echo "== rename / move / cycle =="
want "rename folder" '"name":"Pictures"' "$(A -X PATCH "http://$API/api/folders/$PID" -d '{"name":"Pictures"}')"
FID=$(fid_in "http://$API/api/fs?folder=$PID" "pic.jpg")
A -X PATCH "http://$API/api/files/$FID" -d '{"folderId":0}' >/dev/null
want "file moved to root" '"name":"pic.jpg"' "$(A "http://$API/api/fs")"
want "cannot move folder into own subtree" "invalid move" "$(A -X PATCH "http://$API/api/folders/$PID" -d "{\"parentId\":$SID}")"

echo "== recursive delete frees blobs =="
A -X POST "http://$API/api/files" -H "X-Filename: deep.bin" -H "X-Folder: $SID" --data-binary "DATA" >/dev/null
BEFORE=$(find "$TESTDIR/storage" -type f 2>/dev/null | wc -l)
A -X DELETE "http://$API/api/folders/$PID" >/dev/null
want "folder gone from root" '"folders":[]' "$(A "http://$API/api/fs")"
want "subfolder 404 after parent delete" "folder not found" "$(A "http://$API/api/fs?folder=$SID")"
AFTER=$(find "$TESTDIR/storage" -type f 2>/dev/null | wc -l)
[ "$AFTER" -lt "$BEFORE" ] && ok "blob freed on recursive delete ($BEFORE->$AFTER)" || bad "no blob freed ($BEFORE->$AFTER)"

echo "== usage =="
want "usage reports count" '"files":' "$(A "http://$API/api/usage")"

finish
