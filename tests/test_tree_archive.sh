#!/usr/bin/env bash
# Folder uploads as one tar on real-folder accounts (streamed extraction), plus the
# throttle-not-ban rate limiting for logged-in clients.
source "$(dirname "$0")/lib.sh"
start_server 8132 || exit 1
U="http://$API"
TOK=$(tok_of "$(curl -s "$U/api/auth/register" -d '{"email":"arc@e.cc","password":"supersecret","inviteCode":"test-invite"}')")
TB=$(tok_of "$(curl -s "$U/api/auth/register" -d '{"email":"blob2@e.cc","password":"supersecret","inviteCode":"test-invite"}')")
T=$TOK
kill "$SRV_PID"; wait "$SRV_PID" 2>/dev/null
TR="$TESTDIR/tree/me"; mkdir -p "$TR/Code"
printf 'TREE_ROOT=%s/tree\nTREE_SCAN_MINUTES=0\n' "$TESTDIR" >> "$TESTDIR/config.env"
(cd "$ROOT" && ./cloud_serv admin set-tree --email arc@e.cc --dir me --config "$TESTDIR/config.env" >/dev/null)
launch_server || exit 1
TARS="$TESTDIR/tars"; python3 -I "$ROOT/tests/make_tars.py" "$TARS" >/dev/null
CODE=$(A "$U/api/fs" | tr '}' '\n' | grep -F '"name":"Code"' | grep -o '"id":[0-9]*' | cut -d: -f2)

# upload_tar <tar> <folder name> <parent id> <chunk bytes>  -> prints the complete/abort response
upload_tar() {
  local f="$1" name="$2" parent="$3" cs="$4" size id off=0 r
  size=$(stat -c %s "$f")
  id=$(A -X POST "$U/api/uploads/init" -d "{\"kind\":\"tree-folder\",\"name\":\"$name\",\"size\":$size,\"folderId\":$parent}" | grep -o '"uploadId":"[^"]*"' | cut -d'"' -f4)
  [ -n "$id" ] || { echo "INIT FAILED"; return; }
  while [ "$off" -lt "$size" ]; do
    r=$(dd if="$f" bs=1 skip="$off" count="$cs" status=none 2>/dev/null | A -X PUT "$U/api/uploads/$id" -H "X-Offset: $off" --data-binary @-)
    printf '%s' "$r" | grep -q '"received"' || { echo "$r"; return; }
    off=$(printf '%s' "$r" | grep -o '"received":[0-9]*' | cut -d: -f2)
  done
  A -X POST "$U/api/uploads/$id/complete"
}
leftovers() { find "$TR/.cloud-serv" -mindepth 2 2>/dev/null | wc -l; }

echo "== good archive, odd chunk sizes (headers split across chunks) =="
R=$(upload_tar "$TARS/good.tar" "Proj" "$CODE" 7777)
want "folder upload completes" '"name":"Proj"' "$R"
want "file count reported" '"files":7' "$R"
want "folder count reported (Proj, src, src/lib, empty-folder, deep + 8 levels)" '"folders":13' "$R"
want "symlink entry skipped" '"skipped":1' "$R"
[ "$(cat "$TR/Code/Proj/src/main.js")" = "console.log('hi')" ] && ok "nested file content" || bad "nested file wrong"
[ -d "$TR/Code/Proj/empty-folder" ] && ok "empty folder kept" || bad "empty folder missing"
[ -f "$TR/Code/Proj/deep/level-00-with-a-longish-name/level-01-with-a-longish-name/level-02-with-a-longish-name/level-03-with-a-longish-name/level-04-with-a-longish-name/level-05-with-a-longish-name/level-06-with-a-longish-name/level-07-with-a-longish-name/far.txt" ] && ok "long pax path" || bad "long path missing"
[ -f "$TR/Code/Proj/unicode-éè-日本.txt" ] && ok "unicode name" || bad "unicode name missing"
[ "$(stat -c %s "$TR/Code/Proj/big.bin")" = 1048576 ] && ok "1 MB file intact size" || bad "big file size wrong"
python3 -I -c "import sys;d=open(sys.argv[1],'rb').read();sys.exit(0 if d==bytes(range(256))*4096 else 1)" "$TR/Code/Proj/big.bin" && ok "1 MB file intact bytes" || bad "big file bytes differ"
[ "$(stat -c %Y "$TR/Code/Proj/README.md")" = 1700000000 ] && ok "mtime kept" || bad "mtime not kept"
[ ! -e "$TR/Code/Proj/a-symlink" ] && ok "no symlink created" || bad "symlink created!"
[ "$(leftovers)" = 0 ] && ok "staging cleaned" || bad "staging leftovers: $(leftovers)"
PROJ=$(A "$U/api/fs?folder=$CODE" | tr '}' '\n' | grep -F '"name":"Proj"' | grep -o '"id":[0-9]*' | cut -d: -f2)
want "indexed: Proj lists src" '"name":"src"' "$(A "$U/api/fs?folder=$PROJ")"
want "indexed: usage counts new files" '"files":7' "$(A "$U/api/usage")"
F=$(A "$U/api/search?q=util.js" | grep -o '"id":[0-9]*' | head -1 | cut -d: -f2)
want "indexed file downloads" "export const x = 1;" "$(A "$U/api/files/$F")"

echo "== a tar built by the web app's own code (node) =="
if command -v node >/dev/null 2>&1; then
  node "$ROOT/tests/js_tar.mjs" "$ROOT/web/app.js" "$TESTDIR/js.tar" >/dev/null
  R=$(upload_tar "$TESTDIR/js.tar" "FromBrowser" 0 1048576)
  want "browser-built archive accepted" '"files":5' "$R"
  [ -f "$TR/FromBrowser/café-日本.txt" ] && [ -d "$TR/FromBrowser/empty" ] && [ -f "$TR/FromBrowser/zero.bin" ] && ok "browser tar: unicode, empty folder, 0-byte" || bad "browser tar contents wrong"
  ls "$TR/FromBrowser/level-0-with-a-longish-name/level-1-with-a-longish-name/level-2-with-a-longish-name/level-3-with-a-longish-name/level-4-with-a-longish-name/level-5-with-a-longish-name/level-6-with-a-longish-name/level-7-with-a-longish-name/far.txt" >/dev/null 2>&1 && ok "browser tar: long path via pax" || bad "browser tar long path missing"
  python3 -I -c "import sys;d=open(sys.argv[1],'rb').read();sys.exit(0 if len(d)==3*1024*1024+17 and all(d[i]==(i*7)&255 for i in range(0,len(d),4099)) else 1)" "$TR/FromBrowser/big.bin" && ok "browser tar: 3 MB file byte pattern intact" || bad "browser tar big file corrupted"
else
  echo "  (node not found: skipping browser-built tar check)"
fi

echo "== same name again -> (1) =="
want "second upload lands as Proj (1)" '"name":"Proj (1)"' "$(upload_tar "$TARS/good.tar" "Proj" "$CODE" 65536)"
[ -f "$TR/Code/Proj (1)/README.md" ] && [ -f "$TR/Code/Proj/README.md" ] && ok "original untouched, copy beside it" || bad "clash handling wrong"

echo "== GNU long names, 1-byte-ish chunks for the header =="
want "gnu archive" '"files":2' "$(upload_tar "$TARS/gnu.tar" "Gnu" 0 333)"
[ -f "$TR/Gnu/plain.txt" ] && ok "gnu file placed" || bad "gnu file missing"

echo "== hostile archives are rejected whole, nothing escapes =="
for t in dotdot absolute nested-dotdot; do
  R=$(upload_tar "$TARS/$t.tar" "Bad-$t" 0 512)
  want "$t rejected" "unsafe path in archive" "$R"
  [ ! -e "$TR/Bad-$t" ] && ok "$t: no folder placed" || bad "$t: folder placed"
done
[ ! -e "$TESTDIR/tree/escaped.txt" ] && [ ! -e "$TR/escaped.txt" ] && [ ! -e "$TR/escaped2.txt" ] && [ ! -e "$TESTDIR/escaped2.txt" ] && [ ! -e /tmp/abs-escape.txt ] && ok "no file written outside" || bad "ESCAPED a file!"
want "duplicate entry rejected" "twice" "$(upload_tar "$TARS/dup.tar" "Dup" 0 4096)"
want "truncated rejected" "ended in the middle" "$(upload_tar "$TARS/truncated.tar" "Trunc" 0 65536)"
want "garbage rejected" "not a valid tar" "$(upload_tar "$TARS/garbage.tar" "Garbage" 0 4096)"
[ ! -e "$TR/Dup" ] && [ ! -e "$TR/Trunc" ] && [ ! -e "$TR/Garbage" ] && ok "rejected archives left nothing in the tree" || bad "rejected archive placed"
[ "$(leftovers)" = 0 ] && ok "staging cleaned after rejections" || bad "staging leftovers: $(leftovers)"
R=$(upload_tar "$TARS/odd.tar" "Odd" 0 4096)
want "hardlink + reserved names skipped, rest kept" '"skipped":3' "$R"
[ -f "$TR/Odd/keep.txt" ] && [ ! -e "$TR/Odd/.trash" ] && [ ! -e "$TR/Odd/sub/.cloud-serv" ] && ok "only safe entries created" || bad "unsafe entry created"

echo "== abort + interrupted =="
ID=$(A -X POST "$U/api/uploads/init" -d '{"kind":"tree-folder","name":"Half","size":999999,"folderId":0}' | grep -o '"uploadId":"[^"]*"' | cut -d'"' -f4)
dd if="$TARS/good.tar" bs=10240 count=1 status=none | A -X PUT "$U/api/uploads/$ID" -H "X-Offset: 0" --data-binary @- >/dev/null
A -X DELETE "$U/api/uploads/$ID" >/dev/null
[ "$(leftovers)" = 0 ] && [ ! -e "$TR/Half" ] && ok "abort removes the staging folder" || bad "abort left staging"
ID=$(A -X POST "$U/api/uploads/init" -d '{"kind":"tree-folder","name":"Restart","size":999999,"folderId":0}' | grep -o '"uploadId":"[^"]*"' | cut -d'"' -f4)
dd if="$TARS/good.tar" bs=10240 count=1 status=none | A -X PUT "$U/api/uploads/$ID" -H "X-Offset: 0" --data-binary @- >/dev/null
kill "$SRV_PID"; wait "$SRV_PID" 2>/dev/null; launch_server || exit 1
want "upload after a server restart says start again" "start it again" "$(dd if="$TARS/good.tar" bs=10240 skip=1 count=1 status=none | A -X PUT "$U/api/uploads/$ID" -H "X-Offset: 10240" --data-binary @-)"
[ ! -e "$TR/Restart" ] && ok "interrupted upload not placed" || bad "interrupted upload placed"

echo "== validation =="
want "reserved folder name refused" "invalid filename" "$(A -X POST "$U/api/uploads/init" -d '{"kind":"tree-folder","name":".trash","size":1,"folderId":0}')"
T=$TB
want "blob account can't use folder archives" "need real-folder storage" "$(A -X POST "$U/api/uploads/init" -d '{"kind":"tree-folder","name":"X","size":1,"folderId":0}')"
T=$TOK

echo "== rate limit: logged-in is throttled, never banned; anonymous floods still banned =="
kill "$SRV_PID"; wait "$SRV_PID" 2>/dev/null
printf 'RATE_LIMIT_ENABLED=true\nWRITE_RPM=60\nREAD_RPM=60\nBURST_SIZE=5\nBAN_THRESHOLD=10\nBAN_DURATION=300\n' >> "$TESTDIR/config.env"
launch_server || exit 1
CODES=$(for i in $(seq 1 40); do curl -s -o /dev/null -w '%{http_code} ' -H "authorization: Bearer $T" "$U/api/usage"; done)
printf '%s' "$CODES" | grep -q 429 && ok "logged-in burst gets 429s (throttled)" || bad "no throttling at all"
H=$(curl -s -D - -o /dev/null -H "authorization: Bearer $T" "$U/api/usage" | tr -d '\r' | grep -i '^retry-after' | awk '{print $2}')
[ "$H" = 2 ] && ok "throttle says Retry-After: 2" || bad "retry-after was '$H'"
sleep 3
want "logged-in client recovers after a pause (no ban)" '"files"' "$(A "$U/api/usage")"
for i in $(seq 1 40); do curl -s -o /dev/null "$U/api/health"; done
H=$(curl -s -D - -o /dev/null "$U/api/health" | tr -d '\r' | grep -i '^retry-after' | awk '{print $2}')
[ "$H" = 60 ] && ok "anonymous flood still banned (Retry-After: 60)" || bad "anonymous not banned (retry-after '$H')"
want "banned IP's logged-in requests still work after a pause" '"files"' "$(sleep 3; A "$U/api/usage")"

finish
