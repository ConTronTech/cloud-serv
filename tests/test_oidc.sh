#!/usr/bin/env bash
# Sign in with an OIDC provider (mock IdP): PKCE start, group-gated auto-create,
# email-takeover guard, linking, nonce/iss/aud checks, single-use state.
source "$(dirname "$0")/lib.sh"
IDP=18931
python3 "$(dirname "$0")/mock_oidc.py" $IDP & IDP_PID=$!
trap 'kill $IDP_PID 2>/dev/null' EXIT
sleep 0.4
EXTRA_CONFIG=$'OIDC_ISSUER=http://127.0.0.1:18931\nOIDC_CLIENT_ID=test-client\nOIDC_CLIENT_SECRET=test-secret\nOIDC_ALLOWED_GROUP=cloud-serv-users\nOIDC_BUTTON_LABEL=authentik'
start_server 8128 || exit 1
B="http://$API"

# start -> returns Location with state + nonce; we then "come back" with code=<scenario>.<nonce>
start() {  # start [extra curl args...] -> sets STATE NONCE LOC
  LOC=$(curl -s -o /dev/null -w '%{redirect_url}' "$@" "$B/api/auth/oidc/start${MODE:+?mode=$MODE}")
  STATE=$(printf '%s' "$LOC" | grep -o 'state=[0-9a-f]*' | cut -d= -f2)
  NONCE=$(printf '%s' "$LOC" | grep -o 'nonce=[0-9a-f]*' | cut -d= -f2)
}
callback() {  # callback <scenario> [jar] -> prints Location; cookie saved to jar
  curl -s -o /dev/null -w '%{redirect_url}' ${2:+-c "$2"} "$B/api/auth/oidc/callback?code=$1.$NONCE&state=$STATE"
}

echo "== config + start =="
want "config enabled" '"enabled":true' "$(curl -s "$B/api/auth/oidc/config")"
want "label" '"label":"authentik"' "$(curl -s "$B/api/auth/oidc/config")"
start
want "redirects to IdP authorize" "http://127.0.0.1:18931/authorize?" "$LOC"
want "PKCE S256" "code_challenge_method=S256" "$LOC"
want "callback uri for this host" "redirect_uri=http%3A%2F%2Flocalhost%3A8128%2Fapi%2Fauth%2Foidc%2Fcallback" "$LOC"
[ ${#STATE} -eq 32 ] && ok "state is 128-bit" || bad "state length ${#STATE}"

echo "== new user in allowed group is created =="
J=$(mktemp); L=$(callback alice "$J")
want "alice lands in app" "/#sso" "$L"
want "alice session works" '"email":"alice@sso.test"' "$(curl -s -b "$J" "$B/api/auth/me")"
want "alice has no local password" '"localLogin":false' "$(curl -s -b "$J" "$B/api/auth/identities")"
want "alice cannot unlink her only login" 'only way to sign in' "$(curl -s -b "$J" -X DELETE "$B/api/auth/identities/1")"
start; L=$(callback alice); want "alice second login reuses account" "/#sso" "$L"
want "still one alice account" '"id":' "$(curl -s -b "$J" "$B/api/auth/me")"

echo "== state is single-use and must exist =="
want "replayed state rejected" "sso-error=expired" "$(callback alice)"
STATE=deadbeefdeadbeefdeadbeefdeadbeef; want "unknown state rejected" "sso-error=expired" "$(callback alice)"

echo "== group gate =="
start; want "bob (wrong group) refused" "sso-error=not-allowed" "$(callback bob)"
start; want "dave (no groups, not linked) refused" "sso-error=not-allowed" "$(callback dave)"

echo "== token checks =="
start; want "wrong nonce refused" "sso-error=login-failed" "$(curl -s -o /dev/null -w '%{redirect_url}' "$B/api/auth/oidc/callback?code=alice.0000&state=$STATE")"
start; want "wrong audience refused" "sso-error=login-failed" "$(callback wrongaud-alice)"
start; want "wrong issuer refused" "sso-error=login-failed" "$(callback wrongiss-alice)"
start; want "IdP error param -> cancelled" "sso-error=cancelled" "$(curl -s -o /dev/null -w '%{redirect_url}' "$B/api/auth/oidc/callback?error=access_denied&state=$STATE")"

echo "== no silent takeover of a local account by email =="
T=$(tok_of "$(curl -s "$B/api/auth/register" -d '{"email":"local@e.cc","password":"supersecret","inviteCode":"test-invite"}')")
start; want "carol with local@e.cc refused (email-in-use)" "sso-error=email-in-use" "$(callback carol)"

echo "== linking from a signed-in local account =="
MODE=link; start -H "authorization: Bearer $T"; MODE=
want "link start needs session (with it: to IdP)" "http://127.0.0.1:18931/authorize?" "$LOC"
want "dave linked to local account" "/#sso-linked" "$(callback dave)"
J2=$(mktemp); start; want "dave now signs into the local account" "/#sso" "$(callback dave "$J2")"
want "it is the local account" '"email":"local@e.cc"' "$(curl -s -b "$J2" "$B/api/auth/me")"
IDS=$(curl -s -H "authorization: Bearer $T" "$B/api/auth/identities")
want "identity listed" '"email":"dave@sso.test"' "$IDS"
want "local login still on" '"localLogin":true' "$IDS"
MODE=link; start; MODE=
want "link without session refused" "sso-error=not-signed-in" "$LOC"
MODE=link; start -H "authorization: Bearer $T"; MODE=
want "alice's identity can't be linked to another account" "sso-error=linked-elsewhere" "$(callback alice)"
IID=$(printf '%s' "$IDS" | grep -o '"id":[0-9]*' | head -1 | cut -d: -f2)
want "local account can unlink" '"ok":true' "$(curl -s -H "authorization: Bearer $T" -X DELETE "$B/api/auth/identities/$IID")"
start; want "after unlink dave is refused again" "sso-error=not-allowed" "$(callback dave)"
rm -f "$J" "$J2"
finish
