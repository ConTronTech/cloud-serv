#!/usr/bin/env bash
# "Encrypt my files" preference + safe serving of uploaded content.
source "$(dirname "$0")/lib.sh"
start_server 8127 || exit 1
T=$(tok_of "$(curl -s "http://$API/api/auth/register" -d '{"email":"p@e.cc","password":"supersecret","inviteCode":"test-invite"}')")

echo "== encryptFiles preference =="
want "default is off (FILES_ENCRYPT_DEFAULT unset)" '"encryptFiles":false' "$(A "http://$API/api/auth/me")"
want "turn on" '"encryptFiles":true' "$(A -X PATCH "http://$API/api/auth/me/prefs" -d '{"encryptFiles":true}')"
want "me reflects on" '"encryptFiles":true' "$(A "http://$API/api/auth/me")"
want "turn off" '"encryptFiles":false' "$(A -X PATCH "http://$API/api/auth/me/prefs" -d '{"encryptFiles":false}')"
want "non-boolean rejected" 'encryptFiles' "$(A -X PATCH "http://$API/api/auth/me/prefs" -d '{"encryptFiles":"yes"}')"
want "no auth rejected" 'unauthorized' "$(curl -s -X PATCH "http://$API/api/auth/me/prefs" -d '{"encryptFiles":true}')"

echo "== uploaded content is never served as a live page =="
HID=$(id_of "$(A -X POST "http://$API/api/files" -H "X-Filename: page.html" -H "content-type: text/html" --data-binary '<script>alert(1)</script>')")
H=$(A -D - -o /dev/null "http://$API/api/files/$HID/content")
want "html -> octet-stream" 'Content-Type: application/octet-stream' "$H"
want "html -> attachment" 'Content-Disposition: attachment' "$H"
want "sandbox CSP on content" 'sandbox' "$H"
want "nosniff on content" 'nosniff' "$H"
SID=$(id_of "$(A -X POST "http://$API/api/files" -H "X-Filename: x.svg" -H "content-type: image/svg+xml" --data-binary '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>')")
want "svg -> attachment" 'Content-Disposition: attachment' "$(A -D - -o /dev/null "http://$API/api/files/$SID/content")"
HR=$(A -D - -o /dev/null -H 'Range: bytes=0-3' "http://$API/api/files/$HID/content")
want "range response also octet-stream" 'Content-Type: application/octet-stream' "$HR"
want "download of html is octet-stream" 'Content-Type: application/octet-stream' "$(A -D - -o /dev/null "http://$API/api/files/$HID")"

echo "== safe media still inline =="
PID=$(id_of "$(A -X POST "http://$API/api/files" -H "X-Filename: a.png" -H "content-type: image/png" --data-binary 'PNGDATA')")
P=$(A -D - -o /dev/null "http://$API/api/files/$PID/content")
want "png inline" 'Content-Disposition: inline' "$P"
want "png type kept" 'Content-Type: image/png' "$P"
VID=$(id_of "$(A -X POST "http://$API/api/files" -H "X-Filename: v.mp4" -H "content-type: video/mp4" --data-binary '0123456789')")
V=$(A -D - -o /dev/null -H 'Range: bytes=2-5' "http://$API/api/files/$VID/content")
want "video range 206" ' 206' "$V"
want "video inline" 'Content-Disposition: inline' "$V"
TID=$(id_of "$(A -X POST "http://$API/api/files" -H "X-Filename: n.txt" -H "content-type: text/plain" --data-binary 'hi')")
want "text/plain gets utf-8 charset" 'text/plain; charset=utf-8' "$(A -D - -o /dev/null "http://$API/api/files/$TID/content")"

echo "== plaintext upload round-trips any binary =="
head -c 70000 /dev/urandom > "$TESTDIR/bin.dat"
BID=$(id_of "$(A -X POST "http://$API/api/files" -H "X-Filename: tool.exe" -H "content-type: application/x-msdownload" --data-binary @"$TESTDIR/bin.dat")")
A -o "$TESTDIR/bin.out" "http://$API/api/files/$BID"
[ "$(sha256sum < "$TESTDIR/bin.dat")" = "$(sha256sum < "$TESTDIR/bin.out")" ] && ok "binary identical after download" || bad "binary changed"
want "plain name stored" '"name":"tool.exe"' "$(A "http://$API/api/files")"
finish
