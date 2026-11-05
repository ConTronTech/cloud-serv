#!/usr/bin/env bash
# Sign-up requests (admin approval) + one-time invite codes.
source "$(dirname "$0")/lib.sh"
EXTRA_CONFIG=$'REGISTRATION_REQUESTS=true'
start_server 8130 || exit 1
B="http://$API"
reg() { curl -s -w ' HTTP%{http_code}' "$B/api/auth/register" -d "$1"; }
login() { curl -s "$B/api/auth/login" -d "{\"email\":\"$1\",\"password\":\"$2\"}"; }

echo "== no admin yet: requests are closed =="
want "signup-mode: requests off without an admin" '"requests":false' "$(curl -s "$B/api/auth/signup-mode")"
want "request refused before an admin exists" 'HTTP403' "$(reg '{"email":"early@e.cc","password":"supersecret"}')"
TA=$(tok_of "$(curl -s "$B/api/auth/register" -d '{"email":"admin@e.cc","password":"supersecret","inviteCode":"test-invite"}')")
want "first account is admin" '"role":"admin"' "$(curl -s -H "authorization: Bearer $TA" "$B/api/auth/me")"
want "signup-mode: requests on" '"requests":true' "$(curl -s "$B/api/auth/signup-mode")"

echo "== sign-up request =="
R=$(reg '{"email":"req@e.cc","password":"supersecret","displayName":"Req","note":"hi it is me, from the shop"}')
want "request accepted as pending (202)" '"pending":true} HTTP202' "$R"
want "no session handed out" 'HTTP202' "$(printf '%s' "$R" | grep -v token)"
want "pending can't log in" '"code":"pending"' "$(login req@e.cc supersecret)"
want "wrong password still just invalid (no status leak)" 'invalid credentials' "$(login req@e.cc wrongwrong)"
want "taken email gives the same answer" '"pending":true} HTTP202' "$(reg '{"email":"admin@e.cc","password":"supersecret"}')"
want "wrong invite code is NOT turned into a request" 'HTTP403' "$(reg '{"email":"x@e.cc","password":"supersecret","inviteCode":"CTT-NOPE-NOPE-NOPE"}')"

echo "== admin queue =="
Q=$(curl -s -H "authorization: Bearer $TA" "$B/api/admin/requests")
want "request listed with note" '"note":"hi it is me, from the shop"' "$Q"
want "request listed with email" '"email":"req@e.cc"' "$Q"
RID=$(printf '%s' "$Q" | grep -o '"id":[0-9]*' | head -1 | cut -d: -f2)
TU=$(tok_of "$(curl -s "$B/api/auth/register" -d '{"email":"user@e.cc","password":"supersecret","inviteCode":"test-invite"}')")
want "non-admin can't see the queue" 'admin only' "$(curl -s -H "authorization: Bearer $TU" "$B/api/admin/requests")"
want "non-admin can't approve" 'admin only' "$(curl -s -H "authorization: Bearer $TU" -X POST "$B/api/admin/requests/$RID/approve")"
want "approve" '"ok":true' "$(curl -s -H "authorization: Bearer $TA" -X POST "$B/api/admin/requests/$RID/approve")"
want "approved user can log in" '"token"' "$(login req@e.cc supersecret)"
want "approve twice -> not pending" 'no pending request' "$(curl -s -H "authorization: Bearer $TA" -X POST "$B/api/admin/requests/$RID/approve")"
reg '{"email":"deny@e.cc","password":"supersecret"}' >/dev/null
DID=$(curl -s -H "authorization: Bearer $TA" "$B/api/admin/requests" | grep -o '"id":[0-9]*' | head -1 | cut -d: -f2)
want "deny" '"ok":true' "$(curl -s -H "authorization: Bearer $TA" -X POST "$B/api/admin/requests/$DID/deny")"
want "denied account is gone" 'invalid credentials' "$(login deny@e.cc supersecret)"
want "deny only works on pending accounts" 'no pending request' "$(curl -s -H "authorization: Bearer $TA" -X POST "$B/api/admin/requests/$RID/deny")"
want "denied email can ask again" 'HTTP202' "$(reg '{"email":"deny@e.cc","password":"supersecret"}')"

echo "== one-time invite codes =="
I=$(curl -s -H "authorization: Bearer $TA" -X POST "$B/api/admin/invites" -d '{"label":"for Bently","expiresDays":7}')
CODE=$(printf '%s' "$I" | grep -o '"code":"[^"]*"' | cut -d'"' -f4)
printf '%s' "$CODE" | grep -Eq '^CTT-[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}$' && ok "code format CTT-XXXX-XXXX-XXXX ($CODE)" || bad "code format: $CODE"
L=$(curl -s -H "authorization: Bearer $TA" "$B/api/admin/invites")
want "listed as open with label" '"label":"for Bently"' "$L"
printf '%s' "$L" | grep -q "$CODE" && bad "code leaked in list" || ok "code never shown again in the list"
LOOSE=$(printf '%s' "$CODE" | tr 'A-Z' 'a-z' | tr -d '-')
R=$(curl -s "$B/api/auth/register" -d "{\"email\":\"inv@e.cc\",\"password\":\"supersecret\",\"inviteCode\":\"$LOOSE\"}")
want "invite (any case, no dashes) -> active account at once" '"token"' "$R"
want "invite can't be used twice" 'HTTP403' "$(reg "{\"email\":\"inv2@e.cc\",\"password\":\"supersecret\",\"inviteCode\":\"$CODE\"}")"
want "list shows who used it" '"usedBy":"inv@e.cc"' "$(curl -s -H "authorization: Bearer $TA" "$B/api/admin/invites")"
IID=$(printf '%s' "$I" | grep -o '"id":[0-9]*' | head -1 | cut -d: -f2)
want "used invite can't be revoked" 'no unused invite' "$(curl -s -H "authorization: Bearer $TA" -X DELETE "$B/api/admin/invites/$IID")"
I2=$(curl -s -H "authorization: Bearer $TA" -X POST "$B/api/admin/invites" -d '{"expiresDays":0}')
want "never-expiring invite" '"expiresAt":0' "$I2"
I2ID=$(printf '%s' "$I2" | grep -o '"id":[0-9]*' | head -1 | cut -d: -f2); C2=$(printf '%s' "$I2" | grep -o '"code":"[^"]*"' | cut -d'"' -f4)
want "revoke unused" '"ok":true' "$(curl -s -H "authorization: Bearer $TA" -X DELETE "$B/api/admin/invites/$I2ID")"
want "revoked code is dead" 'HTTP403' "$(reg "{\"email\":\"rv@e.cc\",\"password\":\"supersecret\",\"inviteCode\":\"$C2\"}")"
I3=$(curl -s -H "authorization: Bearer $TA" -X POST "$B/api/admin/invites" -d '{}'); C3=$(printf '%s' "$I3" | grep -o '"code":"[^"]*"' | cut -d'"' -f4)
python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute('UPDATE invites SET expires_at=1 WHERE used_at IS NULL'); c.commit()" "$TESTDIR/cloud.db"
want "expired code is dead" 'HTTP403' "$(reg "{\"email\":\"ex@e.cc\",\"password\":\"supersecret\",\"inviteCode\":\"$C3\"}")"
want "list marks it expired" '"state":"expired"' "$(curl -s -H "authorization: Bearer $TA" "$B/api/admin/invites")"
want "bad expiry rejected" '0-365' "$(curl -s -H "authorization: Bearer $TA" -X POST "$B/api/admin/invites" -d '{"expiresDays":-1}')"
want "non-admin can't make invites" 'admin only' "$(curl -s -H "authorization: Bearer $TU" -X POST "$B/api/admin/invites" -d '{}')"
KEY=$(curl -s -H "authorization: Bearer $TA" -X POST "$B/api/auth/api-keys" -d '{"name":"k"}' | grep -o '"key":"[^"]*"' | cut -d'"' -f4)
want "API key can't make invites" 'unauthorized' "$(curl -s -H "X-API-Key: $KEY" -X POST "$B/api/admin/invites" -d '{}')"

echo "== queue cap =="
for i in $(seq 1 30); do reg "{\"email\":\"flood$i@e.cc\",\"password\":\"supersecret\"}" >/dev/null; done
want "queue capped at 25 waiting" 'HTTP429' "$(reg '{"email":"onemore@e.cc","password":"supersecret"}')"
N=$(curl -s -H "authorization: Bearer $TA" "$B/api/admin/requests" | grep -o '"email"' | wc -l)
[ "$N" -eq 25 ] && ok "exactly 25 waiting" || bad "waiting=$N"
finish
