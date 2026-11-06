#!/usr/bin/env bash
# Quota can't be dodged (chunking, lying sizes, parallel uploads), and one-shot
# things (invites, chunks, approvals) stay one-shot under concurrent requests.
source "$(dirname "$0")/lib.sh"
start_server 8133 || exit 1
B="http://$API"; KB=1024; MB=$((1024*1024))
reg() { tok_of "$(curl -s "$B/api/auth/register" -d "{\"email\":\"$1\",\"password\":\"supersecret\",\"inviteCode\":\"${2:-test-invite}\"}")"; }
TA=$(reg qadmin@e.cc); TU=$(reg quser@e.cc)
AA() { curl -s -H "authorization: Bearer $TA" "$@"; }
AU() { curl -s -H "authorization: Bearer $TU" "$@"; }
uid() { AA "$B/api/admin/users" | python3 -c "import sys,json; print([u['id'] for u in json.load(sys.stdin)['users'] if u['email']=='$1'][0])"; }
UID_U=$(uid quser@e.cc)
quota() { AA -o /dev/null -X PATCH "$B/api/admin/users/$UID_U" -d "{\"storageQuotaBytes\":$1}"; }
used() { AU "$B/api/usage" | grep -o '"used":[0-9]*' | cut -d: -f2; }
wipe() { for id in $(AU "$B/api/files" | grep -o '"id":[0-9]*' | cut -d: -f2); do AU -o /dev/null -X DELETE "$B/api/files/$id"; done; }
W="$TESTDIR/w"; mkdir -p "$W"; J=""   # bare `wait` would also wait on the test server
head -c $((500*KB)) /dev/urandom > "$W/c500"; head -c $((200*KB)) /dev/urandom > "$W/c200"; head -c $((400*KB)) /dev/urandom > "$W/c400"
quota $MB

echo "== chunked upload with no declared size =="
U=$(AU -X POST "$B/api/uploads/init" -d '{"name":"sneak.bin"}' | grep -o '"uploadId":"[^"]*"' | cut -d'"' -f4)
off=0; codes=""
for i in 1 2 3; do c=$(AU -o /dev/null -w '%{http_code}' -X PUT "$B/api/uploads/$U" -H "X-Offset: $off" --data-binary @"$W/c500"); codes="$codes$c "; [ "$c" = 200 ] && off=$((off + 500*KB)); done
[ "$codes" = "200 200 413 " ] && ok "third 500 KB chunk refused (in-progress bytes count): $codes" || bad "chunk codes: $codes"
AU -o /dev/null -X DELETE "$B/api/uploads/$U"
[ "$(used)" = 0 ] && ok "aborting frees the in-progress bytes" || bad "used after abort: $(used)"

echo "== abandoned uploads expire after a day =="
U=$(AU -X POST "$B/api/uploads/init" -d '{"name":"left.bin"}' | grep -o '"uploadId":"[^"]*"' | cut -d'"' -f4)
AU -o /dev/null -X PUT "$B/api/uploads/$U" -H "X-Offset: 0" --data-binary @"$W/c500"
[ "$(find "$TESTDIR" -path '*storage*' -type f | wc -l)" -eq 1 ] && ok "partial blob on disk while in progress" || bad "no partial blob"
python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute('UPDATE upload_sessions SET touched_at = touched_at - 90000'); c.commit()" "$TESTDIR/cloud.db"
U2=$(AU -X POST "$B/api/uploads/init" -d '{"name":"next.bin"}' | grep -o '"uploadId":"[^"]*"' | cut -d'"' -f4)
want "stale session gone" 'not found' "$(AU "$B/api/uploads/$U")"
[ "$(find "$TESTDIR" -path '*storage*' -type f | wc -l)" -eq 1 ] && ok "its blob deleted (only the new empty one left)" || bad "stale blob left on disk"
AU -o /dev/null -X DELETE "$B/api/uploads/$U2"

echo "== client-reported size can't shrink usage =="
want "upload claiming to be 1 byte" '"size":1' "$(AU -X POST "$B/api/files" -H 'X-Filename: lie.bin' -H 'X-Plain-Size: 1' --data-binary @"$W/c400")"
[ "$(used)" = $((400*KB)) ] && ok "usage counts the 400 KB actually stored" || bad "used=$(used)"
want "display size can't exceed the bytes sent" "\"size\":$((200*KB))" "$(AU -X POST "$B/api/files" -H 'X-Filename: big.bin' -H 'X-Plain-Size: 999999999' --data-binary @"$W/c200")"
want "negative display size ignored" "\"size\":$((200*KB))" "$(AU -X POST "$B/api/files" -H 'X-Filename: neg.bin' -H 'X-Plain-Size: -5' --data-binary @"$W/c200")"
wipe

echo "== 20 uploads of 200 KB at once into 1 MB =="
for i in $(seq 1 20); do AU -o "$W/r$i" -w '%{http_code}' -X POST "$B/api/files" -H "X-Filename: p$i.bin" --data-binary @"$W/c200" > "$W/s$i" & J="$J $!"; done; wait $J; J=""
N=$(cat "$W"/s* | grep -o 200 | wc -l)
[ "$N" -eq 5 ] && ok "exactly 5 fit, the rest refused ($N)" || bad "$N of 20 accepted"
[ "$(used)" -le $MB ] && ok "usage $(used) stays within the 1 MB quota" || bad "quota overrun: used=$(used)"
FILES=$(find "$TESTDIR" -path '*storage*' -type f | wc -l); [ "$FILES" -eq "$N" ] && ok "no orphan blobs on disk ($FILES)" || bad "blobs on disk $FILES vs $N files"
wipe

echo "== parallel chunked uploads into 1 MB =="
for i in $(seq 1 6); do ( U=$(AU -X POST "$B/api/uploads/init" -d "{\"name\":\"c$i\"}" | grep -o '"uploadId":"[^"]*"' | cut -d'"' -f4)
  a=$(AU -o /dev/null -w '%{http_code}' -X PUT "$B/api/uploads/$U" -H "X-Offset: 0" --data-binary @"$W/c400")
  [ "$a" = 200 ] && AU -o /dev/null -X POST "$B/api/uploads/$U/complete" || AU -o /dev/null -X DELETE "$B/api/uploads/$U" ) & J="$J $!"; done; wait $J; J=""
[ "$(used)" -le $MB ] && ok "6 parallel 400 KB chunked uploads stop at the quota (used $(used))" || bad "quota overrun: used=$(used)"
wipe

echo "== the same chunk sent twice at once =="
quota null
U=$(AU -X POST "$B/api/uploads/init" -d "{\"name\":\"dup\",\"size\":$((400*KB))}" | grep -o '"uploadId":"[^"]*"' | cut -d'"' -f4)
for i in 1 2 3 4; do AU -o /dev/null -w '%{http_code} ' -X PUT "$B/api/uploads/$U" -H "X-Offset: 0" --data-binary @"$W/c400" > "$W/d$i" & J="$J $!"; done; wait $J; J=""
C=$(cat "$W"/d? | grep -o 200 | wc -l); [ "$C" -eq 1 ] && ok "only one copy accepted, others get offset_mismatch" || bad "$C copies accepted"
FID=$(id_of "$(AU -X POST "$B/api/uploads/$U/complete")")
AU -o "$W/back" "$B/api/files/$FID"; cmp -s "$W/back" "$W/c400" && ok "file intact (no doubled bytes)" || bad "file corrupted"

echo "== one invite code, 15 people at once =="
CODE=$(AA -X POST "$B/api/admin/invites" -d '{"expiresDays":1}' | grep -o '"code":"[^"]*"' | cut -d'"' -f4)
for i in $(seq 1 15); do curl -s "$B/api/auth/register" -d "{\"email\":\"race$i@e.cc\",\"password\":\"supersecret\",\"inviteCode\":\"$CODE\"}" > "$W/i$i" & J="$J $!"; done; wait $J; J=""
G=$(cat "$W"/i* | grep -c '"token"'); [ "$G" -eq 1 ] && ok "exactly one account created" || bad "$G accounts from one invite"
ACT=$(AA "$B/api/admin/users" | grep -o '"email":"race[0-9]*@e.cc"' | wc -l); [ "$ACT" -eq 1 ] && ok "no half-made accounts left behind" || bad "$ACT race accounts listed"

echo "== approving one storage request twice at once =="
quota $MB; AU -o /dev/null -X POST "$B/api/files" -H 'X-Filename: f.bin' --data-binary @"$W/c400"
SID=$(id_of "$(AU -X POST "$B/api/storage-requests" -d "{\"uploadBytes\":$((2*MB))}")")
for i in 1 2 3 4; do AA -o /dev/null -w '%{http_code} ' -X POST "$B/api/admin/storage-requests/$SID/approve" > "$W/a$i" & J="$J $!"; done; wait $J; J=""
A=$(cat "$W"/a? | grep -o 200 | wc -l); [ "$A" -eq 1 ] && ok "approved once, repeats refused" || bad "$A approvals succeeded"
finish
