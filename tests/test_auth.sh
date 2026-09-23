#!/usr/bin/env bash
source "$(dirname "$0")/lib.sh"
start_server 8091 || exit 1

echo "== register / login / me =="
REG=$(curl -s "http://$API/api/auth/register" -H 'content-type: application/json' \
  -d '{"email":"a@e.cc","password":"supersecret","displayName":"Alice","inviteCode":"test-invite"}')
want "register returns token" '"token"' "$REG"
T=$(tok_of "$REG")
want "me works with bearer" '"email":"a@e.cc"' "$(A "http://$API/api/auth/me")"
want "login (correct)" '"token"' "$(curl -s "http://$API/api/auth/login" -d '{"email":"a@e.cc","password":"supersecret"}')"
want "login (wrong)" "invalid credentials" "$(curl -s "http://$API/api/auth/login" -d '{"email":"a@e.cc","password":"nope"}')"
REGURL="http://$API/api/auth/register"
reg() { curl -s -w '|%{http_code}' "$REGURL" -H 'content-type: application/json' -d "$1"; }
R_TAKEN=$(reg '{"email":"a@e.cc","password":"supersecret","inviteCode":"test-invite"}')
R_BADCODE=$(reg '{"email":"free1@e.cc","password":"supersecret","inviteCode":"wrong"}')
R_NOCODE=$(reg '{"email":"free2@e.cc","password":"supersecret"}')
R_BADCODE_TAKEN=$(reg '{"email":"a@e.cc","password":"supersecret","inviteCode":"wrong"}')
want "taken email -> generic message" 'registration is not open' "$R_TAKEN"
[ "$R_TAKEN" = "$R_BADCODE" ] && [ "$R_TAKEN" = "$R_NOCODE" ] && [ "$R_TAKEN" = "$R_BADCODE_TAKEN" ] \
  && ok "taken email / wrong code / missing code: identical body+status" || bad "rejections distinguishable: $R_TAKEN vs $R_BADCODE vs $R_NOCODE"
case "$R_TAKEN" in *'|403') ok "rejection status is 403";; *) bad "rejection status: $R_TAKEN";; esac
want "rejected wrong-code email was not created" "invalid credentials" "$(curl -s "http://$API/api/auth/login" -d '{"email":"free1@e.cc","password":"supersecret"}')"
want "free email + correct code succeeds" '"token"' "$(curl -s "$REGURL" -d '{"email":"ok@e.cc","password":"supersecret","inviteCode":"test-invite"}')"
want "short password rejected" "at least 8" "$(curl -s "http://$API/api/auth/register" -d '{"email":"x@y.zz","password":"short12","inviteCode":"test-invite"}')"

echo "== sessions + logout =="
TX=$(tok_of "$(curl -s "http://$API/api/auth/login" -d '{"email":"a@e.cc","password":"supersecret"}')")
curl -s -X POST "http://$API/api/auth/logout" -H "authorization: Bearer $TX" >/dev/null
want "logout revokes token" "unauthorized" "$(curl -s "http://$API/api/auth/me" -H "authorization: Bearer $TX")"
want "no creds -> 401" "unauthorized" "$(curl -s "http://$API/api/files")"

echo "== api keys =="
AK=$(A -X POST "http://$API/api/auth/api-keys" -d '{"name":"cli"}')
want "api key shown once (csk_)" '"key":"csk_' "$AK"
KEY=$(printf '%s' "$AK" | grep -o '"key":"[^"]*"' | cut -d'"' -f4)
want "api key authenticates" '"files"' "$(curl -s "http://$API/api/files" -H "X-API-Key: $KEY")"
want "bad api key rejected" "unauthorized" "$(curl -s "http://$API/api/files" -H 'X-API-Key: csk_nope')"
KID=$(id_of "$AK")
A -X DELETE "http://$API/api/auth/api-keys/$KID" >/dev/null
want "revoked api key rejected" "unauthorized" "$(curl -s "http://$API/api/files" -H "X-API-Key: $KEY")"

echo "== E2E key material =="
curl -s "http://$API/api/auth/register" -H 'content-type: application/json' \
  -d '{"email":"e@e.cc","password":"AUTHKEYb64xxxxxxxxxxxxxxxx","inviteCode":"test-invite","salt":"deadbeef00112233","wrappedDek":"WDEK","wrappedDekRecovery":"WREC"}' >/dev/null
want "salt lookup (known)" '"salt":"deadbeef00112233"' "$(curl -s "http://$API/api/auth/salt?email=e@e.cc")"
D1=$(curl -s "http://$API/api/auth/salt?email=ghost@x.cc")
D2=$(curl -s "http://$API/api/auth/salt?email=ghost@x.cc")
want "unknown email -> decoy salt" '"salt":"' "$D1"
[ "$D1" = "$D2" ] && ok "decoy salt deterministic" || bad "decoy salt not deterministic"
# The decoy must NOT be the client-computable sha256("cloud-serv-salt-v1|"+email)
# (MV-1): otherwise an attacker recomputes it and detects registered emails.
NAIVE=$(printf '%s' "cloud-serv-salt-v1|ghost@x.cc" | sha256sum | cut -c1-32)
if printf '%s' "$D1" | grep -qF "$NAIVE"; then bad "decoy salt is attacker-computable (sha256)"; else ok "decoy salt not attacker-computable (HMAC-keyed)"; fi
want "login returns wrapped DEK" '"wrappedDek":"WDEK"' "$(curl -s "http://$API/api/auth/login" -d '{"email":"e@e.cc","password":"AUTHKEYb64xxxxxxxxxxxxxxxx"}')"

echo "== registration disabled (empty invite code) =="
kill "$SRV_PID" 2>/dev/null; wait "$SRV_PID" 2>/dev/null
sed -i 's/^REGISTRATION_INVITE_CODE=.*/REGISTRATION_INVITE_CODE=/' "$TESTDIR/config.env"
launch_server || exit 1
R_DIS1=$(reg '{"email":"a@e.cc","password":"supersecret","inviteCode":"test-invite"}')
R_DIS2=$(reg '{"email":"newbie@e.cc","password":"supersecret","inviteCode":""}')
[ "$R_DIS1" = "$R_TAKEN" ] && [ "$R_DIS2" = "$R_TAKEN" ] \
  && ok "registration disabled: same body+status as other rejections" || bad "disabled differs: $R_DIS1 / $R_DIS2 vs $R_TAKEN"

finish
