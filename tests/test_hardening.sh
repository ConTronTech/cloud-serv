#!/usr/bin/env bash
# Auth/session/cookie regression tests: cookie attributes, hashed-at-rest secrets,
# API-key vs session endpoints (M10), invite edge cases, login throttle, concurrency.
source "$(dirname "$0")/lib.sh"
start_server 8102 || exit 1
BASE="http://$API"
J='content-type: application/json'
PW=supersecret

echo "== (a) cookie attributes =="
cookie_check() { # name, headers
  local sc; sc=$(printf '%s' "$2" | grep -i '^set-cookie:' | head -1)
  for a in "HttpOnly" "SameSite=Strict" "Secure" "Path=/"; do
    printf '%s' "$sc" | grep -qF "$a" && ok "$1 Set-Cookie has $a" || bad "$1 Set-Cookie lacks $a ($sc)"
  done
}
H=$(curl -s -D - -o "$TESTDIR/reg.json" "$BASE/api/auth/register" -H "$J" -d "{\"email\":\"c@x.cc\",\"password\":\"$PW\",\"inviteCode\":\"test-invite\"}")
cookie_check register "$H"
REG=$(cat "$TESTDIR/reg.json"); T=$(tok_of "$REG")
H=$(curl -s -D - -o "$TESTDIR/login.json" "$BASE/api/auth/login" -H "$J" -d "{\"email\":\"c@x.cc\",\"password\":\"$PW\"}")
cookie_check login "$H"
LOGIN_BODY=$(cat "$TESTDIR/login.json"); T=$(tok_of "$LOGIN_BODY")
H=$(curl -s -D - -o /dev/null -X POST "$BASE/api/auth/logout" -H "authorization: Bearer $T")
cookie_check logout "$H"
printf '%s' "$H" | grep -i '^set-cookie:' | grep -q 'Max-Age=0' && ok "logout cookie has Max-Age=0" || bad "logout cookie not cleared"
printf '%s' "$H" | grep -i '^set-cookie:' | grep -q 'session=;' && ok "logout cookie value emptied" || bad "logout cookie value not emptied"

echo "== (b) secrets never stored raw / never in responses =="
LB=$(curl -s "$BASE/api/auth/login" -H "$J" -d "{\"email\":\"c@x.cc\",\"password\":\"$PW\"}")
T=$(tok_of "$LB")
AK=$(A -X POST "$BASE/api/auth/api-keys" -d '{"name":"k"}')
KEY=$(printf '%s' "$AK" | grep -o '"key":"[^"]*"' | cut -d'"' -f4)
KID=$(id_of "$AK")
[ -n "$T" ] && [ -n "$KEY" ] && ok "have raw token + raw csk_ key" || bad "missing token/key"
ME=$(A "$BASE/api/auth/me"); AKL=$(A "$BASE/api/auth/api-keys")
sleep 1
DBF=$(ls "$TESTDIR"/cloud.db "$TESTDIR"/cloud.db-wal 2>/dev/null)
cnt() { local n=0 f c; for f in $DBF; do c=$(grep -c -a -F -- "$1" "$f"); n=$((n+c)); done; echo "$n"; }
[ "$(cnt "$T")" = 0 ] && ok "raw session token absent from DB + WAL" || bad "raw session token found in DB/WAL"
[ "$(cnt "$KEY")" = 0 ] && ok "raw csk_ API key absent from DB + WAL" || bad "raw API key found in DB/WAL"
[ "$(cnt "$PW")" = 0 ] && ok "raw password absent from DB + WAL" || bad "raw password found in DB/WAL"
[ "$(cnt "$(printf '%s' "$T" | sha256sum | cut -d' ' -f1)")" -ge 1 ] && ok "sha256(session token) present in DB" || bad "sha256(session token) not in DB"
[ "$(cnt "$(printf '%s' "$KEY" | sha256sum | cut -d' ' -f1)")" -ge 1 ] && ok "sha256(API key) present in DB" || bad "sha256(API key) not in DB"
for pair in "register:$REG" "login:$LB" "me:$ME" "api-keys list:$AKL"; do
  n=${pair%%:*}; b=${pair#*:}
  if printf '%s' "$b" | grep -qi 'password_hash\|pbkdf2\|passwordhash'; then bad "$n response leaks password hash material"; else ok "$n response has no password hash material"; fi
done

echo "== (c) API keys vs session-only endpoints (M10) =="
# The session cookie is sent by hand: curl would not replay a Secure cookie over http.
CK="Cookie: session=$T"
st() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
chk401() { # label, curl args...
  local l="$1"; shift; local c; c=$(st "$@")
  [ "$c" = 401 ] && ok "$l -> 401" || bad "$l -> $c (expected 401)"
}
chk401 "API key alone: POST api-keys"   -X POST "$BASE/api/auth/api-keys" -H "X-API-Key: $KEY" -d '{"name":"z"}'
chk401 "API key alone: GET api-keys"    "$BASE/api/auth/api-keys" -H "X-API-Key: $KEY"
chk401 "API key alone: DELETE api-keys" -X DELETE "$BASE/api/auth/api-keys/$KID" -H "X-API-Key: $KEY"
chk401 "API key alone: GET me"          "$BASE/api/auth/me" -H "X-API-Key: $KEY"
chk401 "key+cookie: POST api-keys"      -X POST "$BASE/api/auth/api-keys" -H "X-API-Key: $KEY" -H "$CK" -d '{"name":"z"}'
chk401 "key+cookie: GET api-keys"       "$BASE/api/auth/api-keys" -H "X-API-Key: $KEY" -H "$CK"
chk401 "key+cookie: DELETE api-keys"    -X DELETE "$BASE/api/auth/api-keys/$KID" -H "X-API-Key: $KEY" -H "$CK"
chk401 "key+cookie: GET me"             "$BASE/api/auth/me" -H "X-API-Key: $KEY" -H "$CK"
chk401 "key+bearer: GET me"             "$BASE/api/auth/me" -H "X-API-Key: $KEY" -H "authorization: Bearer $T"
[ "$(st "$BASE/api/auth/me" -H "$CK")" = 200 ] && ok "cookie alone: GET me 200" || bad "cookie alone: GET me failed"
[ "$(st "$BASE/api/auth/api-keys" -H "$CK")" = 200 ] && ok "cookie alone: GET api-keys 200" || bad "cookie alone: GET api-keys failed"
NK=$(curl -s -X POST "$BASE/api/auth/api-keys" -H "$CK" -d '{"name":"n"}')
NKID=$(id_of "$NK")
want "cookie alone: POST api-keys creates key" '"key":"csk_' "$NK"
[ "$(st -X DELETE "$BASE/api/auth/api-keys/$NKID" -H "$CK")" = 200 ] && ok "cookie alone: DELETE api-keys 200" || bad "cookie alone: DELETE api-keys failed"
[ "$(st "$BASE/api/files" -H "X-API-Key: $KEY")" = 200 ] && ok "API key still works on data route (GET /api/files)" || bad "API key rejected on /api/files"

echo "== (d) invite-gated registration edge cases =="
n=0
rej() { # inviteCode JSON fragment (or "" for none) -> body|status|content-type|has-set-cookie
  n=$((n+1))
  local frag=""; [ -n "$1" ] && frag=",\"inviteCode\":$1"
  curl -s -D "$TESTDIR/rh" -o "$TESTDIR/rb" -w '%{http_code}' "$BASE/api/auth/register" -H "$J" \
    -d "{\"email\":\"inv$n@x.cc\",\"password\":\"$PW\"$frag}" > "$TESTDIR/rs"
  printf '%s|%s|%s|%s' "$(cat "$TESTDIR/rb")" "$(cat "$TESTDIR/rs")" \
    "$(grep -i '^content-type:' "$TESTDIR/rh" | tr -d '\r')" "$(grep -ci '^set-cookie:' "$TESTDIR/rh")"
}
REF=$(rej '"totally-wrong"')
case "$REF" in *'|403|'*) ok "reference wrong-code rejection is 403";; *) bad "reference rejection: $REF";; esac
case "$REF" in *'|0') ok "rejection carries NO Set-Cookie";; *) bad "rejection sets a cookie: $REF";; esac
for v in "12345" "null" '["test-invite"]' '{"a":"test-invite"}' '"test-invit"' '"test-invitex"' '"TEST-INVITE"' '"test-invite "' '""' 'true'; do
  R=$(rej "$v")
  [ "$R" = "$REF" ] && ok "inviteCode $v -> identical rejection (body/status/content-type/no cookie)" || bad "inviteCode $v distinguishable: $R vs $REF"
done
R=$(rej "")
[ "$R" = "$REF" ] && ok "missing inviteCode -> identical rejection" || bad "missing inviteCode distinguishable: $R"
C=$(st "$BASE/api/auth/register" -H "$J" -d "{\"email\":\"not-an-email\",\"password\":\"$PW\",\"inviteCode\":\"test-invite\"}")
[ "$C" = 400 ] && ok "valid code + invalid email -> 400" || bad "valid code + invalid email -> $C"
C=$(st "$BASE/api/auth/register" -H "$J" -d '{"email":"short@x.cc","password":"short12","inviteCode":"test-invite"}')
[ "$C" = 400 ] && ok "valid code + <8 char password -> 400" || bad "valid code + short password -> $C"

echo "== (e) login email length cap =="
L300=$(head -c 300 /dev/zero | tr '\0' 'a')
ALL400=1; for i in $(seq 1 8); do [ "$(st "$BASE/api/auth/login" -d "{\"email\":\"$L300@x.cc\",\"password\":\"x\"}")" = 400 ] || ALL400=0; done
[ "$ALL400" = 1 ] && ok "300-char email -> 400 every time (never throttled/locked)" || bad "300-char email not consistently 400"
C=$(st "$BASE/api/auth/login" -d "{\"email\":\"c@x.cc\",\"password\":\"wrong\"}")
[ "$C" = 401 ] && ok "normal failed login for another account unaffected (401)" || bad "unrelated account got $C"
E254="$(head -c 249 /dev/zero | tr '\0' 'b')@x.cc"
[ "${#E254}" = 254 ] && ok "built 254-char email" || bad "email length ${#E254}"
lastc=""; for i in 1 2 3 4 5; do lastc=$(st "$BASE/api/auth/login" -d "{\"email\":\"$E254\",\"password\":\"w$i\"}"); done
[ "$lastc" = 401 ] && ok "254-char unknown email -> 401 like any unknown email" || bad "254-char email -> $lastc"
[ "$(st "$BASE/api/auth/login" -d "{\"email\":\"$E254\",\"password\":\"w6\"}")" = 429 ] && ok "254-char unknown email throttles after 5 failures" || bad "254-char email not throttled"

echo "== (f) LoginThrottle semantics =="
curl -s "$BASE/api/auth/register" -H "$J" -d "{\"email\":\"attack@x.cc\",\"password\":\"$PW\",\"inviteCode\":\"test-invite\"}" >/dev/null
login() { curl -s -o /dev/null -w '%{http_code}' "$BASE/api/auth/login" -d "{\"email\":\"$1\",\"password\":\"$2\"}"; }
for i in 1 2 3; do login "ATTACK@x.cc" "bad$i" >/dev/null; done
for i in 4 5; do login "attack@x.cc" "bad$i" >/dev/null; done
[ "$(login "AtTaCk@X.cc" bad6)" = 429 ] && ok "case variants share one counter (6th attempt locked)" || bad "case-variant emails have separate counters"
[ "$(login "attack@x.cc" $PW)" = 429 ] && ok "lockout also applies to lowercase form with correct pw" || bad "lowercase not locked"
RA=$(curl -s -D - -o /dev/null "$BASE/api/auth/login" -d "{\"email\":\"attack@x.cc\",\"password\":\"z\"}" | grep -i '^retry-after:' | tr -d '\r' | awk '{print $2}')
case "$RA" in ''|*[!0-9]*) bad "Retry-After not an integer: '$RA'";; *) [ "$RA" -gt 0 ] && ok "Retry-After is a positive integer ($RA)" || bad "Retry-After not positive: $RA";; esac
curl -s "$BASE/api/auth/register" -H "$J" -d "{\"email\":\"reset@x.cc\",\"password\":\"$PW\",\"inviteCode\":\"test-invite\"}" >/dev/null
for i in 1 2 3 4; do login reset@x.cc "bad$i" >/dev/null; done
[ "$(login reset@x.cc $PW)" = 200 ] && ok "success after 4 failures -> 200" || bad "login after 4 failures failed"
ALL=""; for i in 1 2 3 4; do ALL="$ALL $(login reset@x.cc "bad$i")"; done
[ "$ALL" = " 401 401 401 401" ] && ok "success reset counter: 4 more failures still 401 (not locked)" || bad "counter not reset by success:$ALL"
[ "$(login reset@x.cc $PW)" = 200 ] && ok "account still loginable after 4+4 failures split by a success" || bad "account locked despite reset"

echo "== (g) concurrency: atomic reservation =="
curl -s "$BASE/api/auth/register" -H "$J" -d "{\"email\":\"race@x.cc\",\"password\":\"$PW\",\"inviteCode\":\"test-invite\"}" >/dev/null
rm -rf "$TESTDIR/race"; mkdir "$TESTDIR/race"
PIDS=""
for i in $(seq 1 30); do
  curl -s -o /dev/null -w '%{http_code}' "$BASE/api/auth/login" -d "{\"email\":\"race@x.cc\",\"password\":\"wrong$i\"}" > "$TESTDIR/race/$i" &
  PIDS="$PIDS $!"
done
# wait only on the curl jobs -- a bare `wait` would also block on the server's own
# background job started by launch_server, which never exits.
wait $PIDS
N401=$(cat "$TESTDIR"/race/* | grep -o 401 | wc -l); N429=$(cat "$TESTDIR"/race/* | grep -o 429 | wc -l)
echo "  (30 parallel wrong logins: $N401 x 401, $N429 x 429)"
[ "$N401" -le 5 ] && ok "at most 5 of 30 parallel wrong-password logins reached verification (401=$N401)" || bad "throttle bypassed by concurrency: $N401 x 401"
[ "$N429" -ge 25 ] && ok "at least 25 of 30 parallel logins throttled (429=$N429)" || bad "only $N429 x 429 of 30"
[ "$(login race@x.cc $PW)" = 429 ] && ok "correct password still 429 while locked" || bad "correct pw not blocked after parallel burst"

echo "== (h) register does not hash before rejecting a bad invite =="
# Guard against reintroducing PBKDF2-before-invite-check. Wrong-code batch must be >=3x faster.
ms() { echo $(( $(date +%s%N) / 1000000 )); }
S=$(ms); for i in $(seq 1 20); do curl -s -o /dev/null "$BASE/api/auth/register" -H "$J" -d "{\"email\":\"w$i@x.cc\",\"password\":\"$PW\",\"inviteCode\":\"nope\"}"; done; WRONG=$(( $(ms) - S ))
S=$(ms); for i in $(seq 1 20); do curl -s -o /dev/null "$BASE/api/auth/register" -H "$J" -d "{\"email\":\"r$i@x.cc\",\"password\":\"$PW\",\"inviteCode\":\"test-invite\"}"; done; RIGHT=$(( $(ms) - S ))
echo "  (20 wrong-code: ${WRONG}ms, 20 correct-code: ${RIGHT}ms)"
[ $((WRONG * 3)) -le "$RIGHT" ] && ok "wrong-code registrations >=3x faster than hashing ones" || bad "wrong-code batch not >=3x faster (${WRONG}ms vs ${RIGHT}ms): hash before invite check?"

finish
