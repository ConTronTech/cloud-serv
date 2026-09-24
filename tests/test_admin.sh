#!/usr/bin/env bash
# Roles, suspension, and storage-quota admin regression tests.
source "$(dirname "$0")/lib.sh"
start_server 8105 || exit 1

# id_of + a field name -> that field's raw JSON snippet for one user in a list body.
# field_of <json> <id> <field>
field_of() {
  printf '%s' "$1" | grep -o '"id":'"$2"'[^{}]*"'"$3"'":[^,}]*'
}

echo "== bootstrap: first registered account becomes admin =="
T1=$(tok_of "$(curl -s "http://$API/api/auth/register" -d '{"email":"a1@e.cc","password":"supersecret","inviteCode":"test-invite"}')")
ME1=$(curl -s -H "authorization: Bearer $T1" "http://$API/api/auth/me")
want "first user is admin" '"role":"admin"' "$ME1"
want "first user is active" '"status":"active"' "$ME1"
U1=$(id_of "$ME1")

R2=$(curl -s "http://$API/api/auth/register" -d '{"email":"u2@e.cc","password":"supersecret","inviteCode":"test-invite"}')
T2=$(tok_of "$R2"); U2=$(id_of "$R2")
want "second user is a plain user" '"role":"user"' "$(curl -s -H "authorization: Bearer $T2" "http://$API/api/auth/me")"

R3=$(curl -s "http://$API/api/auth/register" -d '{"email":"u3@e.cc","password":"supersecret","inviteCode":"test-invite"}')
T3=$(tok_of "$R3"); U3=$(id_of "$R3")

echo "== admin-only listing =="
LIST=$(curl -s -H "authorization: Bearer $T1" "http://$API/api/admin/users")
want "admin sees u2 in the list" '"email":"u2@e.cc"' "$LIST"
want "admin sees u3 in the list" '"email":"u3@e.cc"' "$LIST"
want "listing exposes storage aggregates" '"storageUsedBytes"' "$LIST"
printf '%s' "$LIST" | grep -q '"name"' && bad "admin listing leaks a filename field" || ok "admin listing has no filename field"

want "non-admin GET /api/admin/users -> 403" "admin only" "$(curl -s -H "authorization: Bearer $T2" "http://$API/api/admin/users")"
want "unauthenticated GET /api/admin/users -> 401" "unauthorized" "$(curl -s "http://$API/api/admin/users")"

echo "== admin cannot browse a user's actual files (endpoint must not exist) =="
want "no such admin file-browsing route" "404" "$(curl -s -o /dev/null -w '%{http_code}' -H "authorization: Bearer $T1" "http://$API/api/admin/users/$U2/files")"

echo "== role changes =="
want "promote u2 to admin" '"role":"admin"' \
  "$(curl -s -H "authorization: Bearer $T1" -X PATCH "http://$API/api/admin/users/$U2" -d '{"role":"admin"}')"
want "u1 can now demote itself (u2 is still admin)" '"role":"user"' \
  "$(curl -s -H "authorization: Bearer $T1" -X PATCH "http://$API/api/admin/users/$U1" -d '{"role":"user"}')"
# Restore: u2 (now the only admin) promotes u1 back, then demotes itself again,
# so the rest of this file doesn't depend on which of the two ended up admin.
curl -s -H "authorization: Bearer $T2" -X PATCH "http://$API/api/admin/users/$U1" -d '{"role":"admin"}' >/dev/null
curl -s -H "authorization: Bearer $T1" -X PATCH "http://$API/api/admin/users/$U2" -d '{"role":"user"}' >/dev/null

want "cannot demote the sole remaining admin" "cannot remove the last admin" \
  "$(curl -s -H "authorization: Bearer $T1" -X PATCH "http://$API/api/admin/users/$U1" -d '{"role":"user"}')"
want "non-admin cannot patch roles" "admin only" \
  "$(curl -s -H "authorization: Bearer $T2" -X PATCH "http://$API/api/admin/users/$U3" -d '{"role":"admin"}')"

echo "== suspension =="
want "suspend u2" '"status":"suspended"' "$(curl -s -H "authorization: Bearer $T1" -X PATCH "http://$API/api/admin/users/$U2" -d '{"suspended":true}')"
want "u2's existing session is immediately rejected" "unauthorized" "$(curl -s -H "authorization: Bearer $T2" "http://$API/api/auth/me")"
want "u2 cannot log back in while suspended" "account suspended" \
  "$(curl -s "http://$API/api/auth/login" -d '{"email":"u2@e.cc","password":"supersecret"}')"
want "wrong password on a suspended account still says invalid credentials (no status leak)" "invalid credentials" \
  "$(curl -s "http://$API/api/auth/login" -d '{"email":"u2@e.cc","password":"wrongpassword"}')"

curl -s -H "authorization: Bearer $T1" -X PATCH "http://$API/api/admin/users/$U2" -d '{"suspended":false}' >/dev/null
NEWLOGIN=$(curl -s "http://$API/api/auth/login" -d '{"email":"u2@e.cc","password":"supersecret"}')
want "un-suspended account can log in again" '"token"' "$NEWLOGIN"

want "cannot suspend the sole remaining admin" "cannot suspend the last admin" \
  "$(curl -s -H "authorization: Bearer $T1" -X PATCH "http://$API/api/admin/users/$U1" -d '{"suspended":true}')"

echo "== storage quota =="
want "unlimited by default" '"storageQuotaBytes":null' "$(field_of "$LIST" "$U3" storageQuotaBytes)"

QP=$(curl -s -H "authorization: Bearer $T1" -X PATCH "http://$API/api/admin/users/$U3" -d '{"storageQuotaBytes":100}')
want "quota set to 100 bytes" '"storageQuotaBytes":100' "$QP"

want "upload within quota succeeds" '"id"' \
  "$(curl -s -H "authorization: Bearer $T3" -H "X-Filename: small.bin" -X POST "http://$API/api/files" --data-binary "0123456789")"
BIG=$(head -c 200 /dev/zero | tr '\0' 'x')
want "upload over quota is rejected (413)" "storage quota exceeded" \
  "$(curl -s -H "authorization: Bearer $T3" -H "X-Filename: big.bin" -X POST "http://$API/api/files" --data-binary "$BIG")"
want "chunked init over quota is rejected" "storage quota exceeded" \
  "$(curl -s -H "authorization: Bearer $T3" -X POST "http://$API/api/uploads/init" -d '{"name":"huge.bin","size":100000}')"

curl -s -H "authorization: Bearer $T1" -X PATCH "http://$API/api/admin/users/$U3" -d '{"storageQuotaBytes":null}' >/dev/null
AFTER_CLEAR=$(curl -s -H "authorization: Bearer $T1" "http://$API/api/admin/users")
want "clearing the quota (null) makes it unlimited again" '"storageQuotaBytes":null' "$(field_of "$AFTER_CLEAR" "$U3" storageQuotaBytes)"
want "large upload now succeeds after quota cleared" '"id"' \
  "$(curl -s -H "authorization: Bearer $T3" -H "X-Filename: big2.bin" -X POST "http://$API/api/files" --data-binary "$BIG")"

echo "== default quota applies to new registrations =="
kill "$SRV_PID" 2>/dev/null; wait "$SRV_PID" 2>/dev/null
echo "DEFAULT_STORAGE_QUOTA_GB=1" >> "$TESTDIR/config.env"
launch_server || exit 1

R4=$(curl -s "http://$API/api/auth/register" -d '{"email":"u4@e.cc","password":"supersecret","inviteCode":"test-invite"}')
U4=$(id_of "$R4")
ADMIN_LOGIN=$(curl -s "http://$API/api/auth/login" -d '{"email":"a1@e.cc","password":"supersecret"}')
T1B=$(tok_of "$ADMIN_LOGIN")
LIST2=$(curl -s -H "authorization: Bearer $T1B" "http://$API/api/admin/users")
want "new registration gets the 1GB default quota" '"storageQuotaBytes":1073741824' "$(field_of "$LIST2" "$U4" storageQuotaBytes)"

finish
