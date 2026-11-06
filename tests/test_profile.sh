#!/usr/bin/env bash
# Profile pictures: only real images, size cap, session-only, served safely.
source "$(dirname "$0")/lib.sh"
start_server 8131 || exit 1
B="http://$API"
T=$(tok_of "$(curl -s "$B/api/auth/register" -d '{"email":"pic@e.cc","password":"supersecret","inviteCode":"test-invite"}')")
python3 -c "import sys; open(sys.argv[1],'wb').write(b'\xff\xd8\xff\xe0' + b'JFIF' + b'\x00'*2000)" "$TESTDIR/a.jpg"
python3 -c "import sys; open(sys.argv[1],'wb').write(b'\x89PNG\r\n\x1a\n' + b'\x00'*500)" "$TESTDIR/a.png"
python3 -c "import sys; open(sys.argv[1],'wb').write(b'\xff\xd8\xff\xe0' + b'\x00'*(310*1024))" "$TESTDIR/big.jpg"

want "no picture yet" '"avatarVersion":0' "$(A "$B/api/auth/me")"
want "GET with none -> 404" 'no picture' "$(A "$B/api/auth/me/avatar")"
want "upload jpeg" '"avatarVersion":' "$(A -X PUT "$B/api/auth/me/avatar" -H 'content-type: image/jpeg' --data-binary @"$TESTDIR/a.jpg")"
want "me shows a version" '"avatarVersion":1' "$(A "$B/api/auth/me" | sed 's/"avatarVersion":1[0-9]*/"avatarVersion":1/')"
H=$(A -D - -o "$TESTDIR/got" "$B/api/auth/me/avatar")
want "served as image/jpeg" 'Content-Type: image/jpeg' "$H"
want "nosniff" 'nosniff' "$H"
want "sandboxed" 'sandbox' "$H"
cmp -s "$TESTDIR/a.jpg" "$TESTDIR/got" && ok "bytes identical" || bad "bytes differ"
want "png accepted" '"avatarVersion":' "$(A -X PUT "$B/api/auth/me/avatar" --data-binary @"$TESTDIR/a.png")"
want "png type from content, not header" 'Content-Type: image/png' "$(A -D - -o /dev/null "$B/api/auth/me/avatar")"
want "html refused" 'JPEG, PNG or WebP' "$(A -X PUT "$B/api/auth/me/avatar" -H 'content-type: image/jpeg' --data-binary '<svg onload=alert(1)>')"
want "too big refused" 'under 300 KB' "$(A -X PUT "$B/api/auth/me/avatar" --data-binary @"$TESTDIR/big.jpg")"
want "empty refused" 'under 300 KB' "$(A -X PUT "$B/api/auth/me/avatar" --data-binary '')"
KEY=$(A -X POST "$B/api/auth/api-keys" -d '{"name":"k"}' | grep -o '"key":"[^"]*"' | cut -d'"' -f4)
want "API key can't change it" 'unauthorized' "$(curl -s -H "X-API-Key: $KEY" -X PUT "$B/api/auth/me/avatar" --data-binary @"$TESTDIR/a.jpg")"
want "no auth can't read it" 'unauthorized' "$(curl -s "$B/api/auth/me/avatar")"
T2=$(tok_of "$(curl -s "$B/api/auth/register" -d '{"email":"other@e.cc","password":"supersecret","inviteCode":"test-invite"}')")
want "other user gets their own (none), not mine" 'no picture' "$(curl -s -H "authorization: Bearer $T2" "$B/api/auth/me/avatar")"
want "remove" '"ok":true' "$(A -X DELETE "$B/api/auth/me/avatar")"
want "gone" 'no picture' "$(A "$B/api/auth/me/avatar")"
finish
