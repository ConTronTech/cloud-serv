#!/usr/bin/env bash
source "$(dirname "$0")/lib.sh"
start_server 8097 || exit 1
T1=$(tok_of "$(curl -s "http://$API/api/auth/register" -d '{"email":"s1@e.cc","password":"supersecret"}')")
T2=$(tok_of "$(curl -s "http://$API/api/auth/register" -d '{"email":"s2@e.cc","password":"supersecret"}')")

echo "== SQL injection =="
printf '{"email":"s1@e.cc\\u0027 OR 1=1--","password":"x"}' > "$TESTDIR/sqli.json"
want "SQLi in email -> no bypass" "invalid credentials" "$(curl -s "http://$API/api/auth/login" -H 'content-type: application/json' --data-binary @"$TESTDIR/sqli.json")"
curl -s -H "authorization: Bearer $T1" -X POST "http://$API/api/files" -H "X-Filename: x.txt" --data-binary "y'); DROP TABLE files;--" >/dev/null
want "files table intact after injection" '"files"' "$(curl -s -H "authorization: Bearer $T1" "http://$API/api/files")"

echo "== path traversal =="
want "traversal in X-Filename rejected" "invalid filename" "$(curl -s -H "authorization: Bearer $T1" -X POST "http://$API/api/files" -H 'X-Filename: ../../../../etc/passwd' --data-binary d)"
if curl -s "http://$API/%2e%2e%2fconfig.env" | grep -q SESSION_SECONDS; then bad "static traversal leaks config"; else ok "static traversal blocked"; fi

echo "== IDOR (files, folders, notes) =="
FID=$(id_of "$(curl -s -H "authorization: Bearer $T1" -X POST "http://$API/api/files" -H 'X-Filename: secret.txt' --data-binary 'sekret')")
want "cross-user download -> 404" "not found" "$(curl -s -H "authorization: Bearer $T2" "http://$API/api/files/$FID")"
want "cross-user delete -> 404" "not found" "$(curl -s -H "authorization: Bearer $T2" -X DELETE "http://$API/api/files/$FID")"
DID=$(id_of "$(curl -s -H "authorization: Bearer $T1" -X POST "http://$API/api/folders" -d '{"name":"priv"}')")
want "cross-user folder rename -> 404" "not found" "$(curl -s -H "authorization: Bearer $T2" -X PATCH "http://$API/api/folders/$DID" -d '{"name":"hax"}')"
NID=$(id_of "$(curl -s -H "authorization: Bearer $T1" -X POST "http://$API/api/notes" -d '{"title":"p"}')")
want "cross-user note read -> 404" "not found" "$(curl -s -H "authorization: Bearer $T2" "http://$API/api/notes/$NID")"

echo "== auth bypass =="
want "no creds" "unauthorized" "$(curl -s "http://$API/api/files")"
want "garbage token" "unauthorized" "$(curl -s "http://$API/api/files" -H 'authorization: Bearer deadbeef')"
want "bad key no fallthrough" "unauthorized" "$(curl -s "http://$API/api/files" -H 'X-API-Key: bad' -H "authorization: Bearer $T1")"

echo "== CSRF / CORS =="
# A cross-origin whose authority merely CONTAINS our host as a substring must be
# blocked (regression for the old find(host)!=npos check).
want "CSRF substring-origin blocked" "cross-origin" "$(curl -s -H "authorization: Bearer $T1" -H "Origin: http://$API.attacker.com" -X POST "http://$API/api/folders" -d '{"name":"x"}')"
# True same-origin still passes the CSRF check.
want "same-origin POST allowed" '"folder"' "$(curl -s -H "authorization: Bearer $T1" -H "Origin: http://$API" -X POST "http://$API/api/folders" -d '{"name":"ok"}')"
# With no CORS origins configured, preflight must not echo Allow-Origin.
if curl -s -i -X OPTIONS "http://$API/api/files" -H "Origin: http://evil.com" | grep -qi "access-control-allow-origin"; then bad "CORS echoes unconfigured origin"; else ok "CORS denies unconfigured origin"; fi

echo "== input validation + logout =="
want "malformed json" "invalid json" "$(curl -s "http://$API/api/auth/login" --data-binary '{bad')"
TX=$(tok_of "$(curl -s "http://$API/api/auth/login" -d '{"email":"s1@e.cc","password":"supersecret"}')")
curl -s -X POST "http://$API/api/auth/logout" -H "authorization: Bearer $TX" >/dev/null
want "revoked session unauthorized" "unauthorized" "$(curl -s "http://$API/api/auth/me" -H "authorization: Bearer $TX")"

finish
