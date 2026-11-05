#!/usr/bin/env bash
# Storage limits: usage shows the quota; asking for more; admin approve / other amount / deny.
source "$(dirname "$0")/lib.sh"
start_server 8133 || exit 1
B="http://$API"
TA=$(tok_of "$(curl -s "$B/api/auth/register" -d '{"email":"sa@e.cc","password":"supersecret","inviteCode":"test-invite"}')")
TU=$(tok_of "$(curl -s "$B/api/auth/register" -d '{"email":"su@e.cc","password":"supersecret","inviteCode":"test-invite"}')")
UID2=$(curl -s -H "authorization: Bearer $TU" "$B/api/auth/me" | grep -o '"id":[0-9]*' | head -1 | cut -d: -f2)
AU() { curl -s -H "authorization: Bearer $TU" "$@"; }
AA() { curl -s -H "authorization: Bearer $TA" "$@"; }
MB=1048576

want "usage: unlimited -> quota null" '"quota":null' "$(AU "$B/api/usage")"
want "unlimited can't ask" 'already unlimited' "$(AU -X POST "$B/api/storage-requests" -d '{"requestedBytes":1000}')"
AA -X PATCH "$B/api/admin/users/$UID2" -d "{\"storageQuotaBytes\":$((1*MB))}" >/dev/null
want "usage shows the limit" "\"quota\":$MB" "$(AU "$B/api/usage")"
head -c $((900*1024)) /dev/urandom > "$TESTDIR/f1"; head -c $((300*1024)) /dev/urandom > "$TESTDIR/f2"
want "upload that fits" '"id"' "$(AU -X POST "$B/api/files" -H 'X-Filename: f1' --data-binary @"$TESTDIR/f1")"
want "upload past the limit refused" 'quota exceeded' "$(AU -X POST "$B/api/files" -H 'X-Filename: f2' --data-binary @"$TESTDIR/f2")"
want "chunked init past the limit refused" 'quota exceeded' "$(AU -X POST "$B/api/uploads/init" -d "{\"name\":\"big\",\"size\":$((300*1024))}")"

echo "== asking =="
want "must ask for more than now" 'more than your current' "$(AU -X POST "$B/api/storage-requests" -d "{\"requestedBytes\":$MB}")"
want "integer required" 'requestedBytes' "$(AU -X POST "$B/api/storage-requests" -d '{"requestedBytes":"lots"}')"
R=$(AU -X POST "$B/api/storage-requests" -d "{\"requestedBytes\":$((2*MB)),\"message\":\"for the arc videos\"}")
want "request created" '"status":"pending"' "$R"
R2=$(AU -X POST "$B/api/storage-requests" -d "{\"requestedBytes\":$((3*MB)),\"message\":\"actually a bit more\"}")
want "a new request replaces the pending one" "\"requestedBytes\":$((3*MB))" "$R2"
L=$(AA "$B/api/admin/storage-requests")
N=$(printf '%s' "$L" | grep -o '"email":"su@e.cc"' | wc -l); [ "$N" -eq 1 ] && ok "only one pending per person" || bad "pending count $N"
want "admin sees used/limit/message" '"message":"actually a bit more"' "$L"
want "admin sees usage" '"usedBytes":921600' "$L"
want "mine shows pending" '"status":"pending"' "$(AU "$B/api/storage-requests/mine")"
want "non-admin can't list" 'admin only' "$(AU "$B/api/admin/storage-requests")"
SID=$(printf '%s' "$L" | grep -o '"id":[0-9]*' | head -1 | cut -d: -f2)
want "non-admin can't approve" 'admin only' "$(AU -X POST "$B/api/admin/storage-requests/$SID/approve")"
KEY=$(AU -X POST "$B/api/auth/api-keys" -d '{"name":"k"}' | grep -o '"key":"[^"]*"' | cut -d'"' -f4)
want "API key can't ask" 'unauthorized' "$(curl -s -H "X-API-Key: $KEY" -X POST "$B/api/storage-requests" -d "{\"requestedBytes\":$((5*MB))}")"

echo "== deciding =="
want "approve with another amount" "\"quotaBytes\":$((4*MB))" "$(AA -X POST "$B/api/admin/storage-requests/$SID/approve" -d "{\"grantBytes\":$((4*MB))}")"
want "limit raised" "\"quota\":$((4*MB))" "$(AU "$B/api/usage")"
want "mine shows approved" '"status":"approved"' "$(AU "$B/api/storage-requests/mine")"
want "the upload now fits" '"id"' "$(AU -X POST "$B/api/files" -H 'X-Filename: f2' --data-binary @"$TESTDIR/f2")"
want "can't decide twice" 'no pending storage' "$(AA -X POST "$B/api/admin/storage-requests/$SID/approve")"
R3=$(AU -X POST "$B/api/storage-requests" -d "{\"requestedBytes\":$((10*MB))}"); S3=$(printf '%s' "$R3" | grep -o '"id":[0-9]*' | head -1 | cut -d: -f2)
want "deny" '"ok":true' "$(AA -X POST "$B/api/admin/storage-requests/$S3/deny")"
want "limit unchanged after deny" "\"quota\":$((4*MB))" "$(AU "$B/api/usage")"
want "mine shows denied" '"status":"denied"' "$(AU "$B/api/storage-requests/mine")"
want "bad grant rejected" 'invalid amount' "$(AA -X POST "$B/api/admin/storage-requests/$(printf '%s' "$(AU -X POST "$B/api/storage-requests" -d "{\"requestedBytes\":$((6*MB))}")" | grep -o '"id":[0-9]*' | head -1 | cut -d: -f2)/approve" -d '{"grantBytes":-5}')"
finish
