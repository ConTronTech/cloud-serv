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

echo "== login hardening =="
LOGIN="http://$API/api/auth/login"
LONG=$(head -c 300 /dev/zero | tr '\0' 'a')
C=$(curl -s -o /dev/null -w '%{http_code}' "$LOGIN" -d "{\"email\":\"$LONG@e.cc\",\"password\":\"x\"}")
[ "$C" = "400" ] && ok "over-254-char login email -> 400" || bad "long email status: $C"
lockseq() { # email, correct-password
  local i out c
  for i in 1 2 3 4 5; do curl -s -o /dev/null "$LOGIN" -d "{\"email\":\"$1\",\"password\":\"wrong$i\"}"; done
  out=$(curl -s -i "$LOGIN" -d "{\"email\":\"$1\",\"password\":\"wrong6\"}")
  case "$out" in *' 429'*) ok "$1: 6th attempt 429";; *) bad "$1: 6th not 429: $(printf '%s' "$out" | head -1)";; esac
  printf '%s' "$out" | grep -qi '^retry-after: [0-9]' && ok "$1: Retry-After present" || bad "$1: no Retry-After"
  c=$(curl -s -o /dev/null -w '%{http_code}' "$LOGIN" -d "{\"email\":\"$1\",\"password\":\"$2\"}")
  [ "$c" = "429" ] && ok "$1: 7th (correct pw while locked) 429" || bad "$1: 7th status $c"
}
lockseq "e@e.cc" "AUTHKEYb64xxxxxxxxxxxxxxxx"
lockseq "nobody-here@e.cc" "whatever123"
C=$(curl -s -o /dev/null -w '%{http_code}' "$LOGIN" -d '{"email":"a@e.cc","password":"supersecret"}')
[ "$C" = "200" ] && ok "unrelated account unaffected by lockouts" || bad "a@e.cc login status $C"

echo "== /me is session-only =="
AK3=$(A -X POST "http://$API/api/auth/api-keys" -d '{"name":"me-test"}')
KEY3=$(printf '%s' "$AK3" | grep -o '"key":"[^"]*"' | cut -d'"' -f4)
R=$(curl -s -w '|%{http_code}' "http://$API/api/auth/me" -H "X-API-Key: $KEY3")
case "$R" in *'|401') ok "/me with API key -> 401";; *) bad "/me with API key: $R";; esac
printf '%s' "$R" | grep -q 'wrappedDek' && bad "/me leaked wrappedDek to API key" || ok "/me API key response has no wrappedDek"
JAR="$TESTDIR/jar"
curl -s -c "$JAR" "$LOGIN" -d '{"email":"a@e.cc","password":"supersecret"}' >/dev/null
ME_C=$(curl -s -b "$JAR" "http://$API/api/auth/me")
want "/me with session cookie returns salt" '"salt"' "$ME_C"
want "/me with session cookie returns wrappedDek" '"wrappedDek"' "$ME_C"
ME_B=$(A "http://$API/api/auth/me")
want "/me with bearer returns salt+wrappedDek" '"wrappedDek"' "$ME_B"

echo "== registration disabled (empty invite code) =="
kill "$SRV_PID" 2>/dev/null; wait "$SRV_PID" 2>/dev/null
sed -i 's/^REGISTRATION_INVITE_CODE=.*/REGISTRATION_INVITE_CODE=/' "$TESTDIR/config.env"
launch_server || exit 1
R_DIS1=$(reg '{"email":"a@e.cc","password":"supersecret","inviteCode":"test-invite"}')
R_DIS2=$(reg '{"email":"newbie@e.cc","password":"supersecret","inviteCode":""}')
[ "$R_DIS1" = "$R_TAKEN" ] && [ "$R_DIS2" = "$R_TAKEN" ] \
  && ok "registration disabled: same body+status as other rejections" || bad "disabled differs: $R_DIS1 / $R_DIS2 vs $R_TAKEN"

finish
