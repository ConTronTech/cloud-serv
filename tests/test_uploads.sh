#!/usr/bin/env bash
source "$(dirname "$0")/lib.sh"
start_server 8094 || exit 1
T=$(tok_of "$(curl -s "http://$API/api/auth/register" -d '{"email":"u@e.cc","password":"supersecret","inviteCode":"test-invite"}')")

echo "== chunked upload + integrity =="
head -c 25000 /dev/urandom > "$TESTDIR/big.bin"
SUM_IN=$(sha256sum "$TESTDIR/big.bin" | cut -d' ' -f1)
INIT=$(A -X POST "http://$API/api/uploads/init" -d '{"name":"big.bin","size":25000}')
want "init returns uploadId" '"uploadId"' "$INIT"
UPID=$(printf '%s' "$INIT" | grep -o '"uploadId":"[^"]*"' | cut -d'"' -f4)
split -b 10000 "$TESTDIR/big.bin" "$TESTDIR/chunk_"
off=0
for ch in "$TESTDIR"/chunk_*; do
  R=$(A -X PUT "http://$API/api/uploads/$UPID" -H "X-Offset: $off" --data-binary @"$ch")
  off=$(printf '%s' "$R" | grep -o '"received":[0-9]*' | cut -d: -f2)
done
want "all bytes received" "25000" "$off"
CMP=$(A -X POST "http://$API/api/uploads/$UPID/complete")
want "complete returns size" '"size":25000' "$CMP"
FID=$(id_of "$CMP")
A "http://$API/api/files/$FID" -o "$TESTDIR/out.bin"
SUM_OUT=$(sha256sum "$TESTDIR/out.bin" | cut -d' ' -f1)
[ "$SUM_IN" = "$SUM_OUT" ] && ok "assembled file matches original (sha256)" || bad "checksum mismatch"

echo "== resume / offset mismatch / abort =="
INIT2=$(A -X POST "http://$API/api/uploads/init" -d '{"name":"r.bin","size":100}')
U2=$(printf '%s' "$INIT2" | grep -o '"uploadId":"[^"]*"' | cut -d'"' -f4)
A -X PUT "http://$API/api/uploads/$U2" -H "X-Offset: 0" --data-binary "0123456789" >/dev/null
want "status shows partial" '"received":10' "$(A "http://$API/api/uploads/$U2")"
want "wrong offset -> 409 w/ received" '"received":10' "$(A -X PUT "http://$API/api/uploads/$U2" -H "X-Offset: 999" --data-binary "x")"
want "abort works" '"ok":true' "$(A -X DELETE "http://$API/api/uploads/$U2")"

finish
