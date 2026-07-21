#!/usr/bin/env bash
source "$(dirname "$0")/lib.sh"
start_server 8092 || exit 1
T=$(tok_of "$(curl -s "http://$API/api/auth/register" -d '{"email":"f@e.cc","password":"supersecret"}')")

echo "== upload / list / download =="
UP=$(A -X POST "http://$API/api/files" -H "X-Filename: hello.txt" -H "content-type: text/plain" --data-binary "hello world")
want "upload returns id+size" '"size":11' "$UP"
FID=$(id_of "$UP")
want "list shows file" '"name":"hello.txt"' "$(A "http://$API/api/files")"
want "download returns content" "hello world" "$(A "http://$API/api/files/$FID")"

echo "== unicode + spaces (X-Filename decoded) =="
A -X POST "http://$API/api/files" -H "X-Filename: My%20Report%20caf%C3%A9.pdf" -H "content-type: application/pdf" --data-binary "x" >/dev/null
want "name decoded (space + unicode)" 'My Report caf' "$(A "http://$API/api/files")"

echo "== 0-byte file allowed =="
want "empty upload ok" '"size":0' "$(A -X POST "http://$API/api/files" -H "X-Filename: empty.txt" --data-binary "")"

echo "== content endpoint + Range =="
A -X POST "http://$API/api/files" -H "X-Filename: az.txt" -H "content-type: text/plain" --data-binary "ABCDEFGHIJKLMNOPQRSTUVWXYZ" >/dev/null
AID=$(A "http://$API/api/files" | tr '}' '\n' | grep 'az.txt' | grep -o '"id":[0-9]*' | head -1 | cut -d: -f2)
H=$(A -D - -o /tmp/range_out "http://$API/api/files/$AID/content" -H "Range: bytes=5-9")
want "range -> 206" "206" "$H"
want "content-range header" "Content-Range: bytes 5-9/26" "$H"
want "range body FGHIJ" "FGHIJ" "$(cat /tmp/range_out)"; rm -f /tmp/range_out

echo "== delete =="
want "delete ok" '"ok":true' "$(A -X DELETE "http://$API/api/files/$FID")"
want "download after delete -> 404" "not found" "$(A "http://$API/api/files/$FID")"

finish
