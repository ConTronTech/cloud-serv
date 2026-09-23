#!/usr/bin/env bash
source "$(dirname "$0")/lib.sh"
start_server 8095 || exit 1
T1=$(tok_of "$(curl -s "http://$API/api/auth/register" -d '{"email":"n1@e.cc","password":"supersecret","inviteCode":"test-invite"}')")
T2=$(tok_of "$(curl -s "http://$API/api/auth/register" -d '{"email":"n2@e.cc","password":"supersecret","inviteCode":"test-invite"}')")

echo "== notes CRUD =="
C=$(curl -s -H "authorization: Bearer $T1" -X POST "http://$API/api/notes" -d '{"title":"Shopping","body":"milk\neggs"}')
want "create returns body" '"body":"milk\neggs"' "$C"
NID=$(id_of "$C")
want "get full note" '"title":"Shopping"' "$(curl -s -H "authorization: Bearer $T1" "http://$API/api/notes/$NID")"
L=$(curl -s -H "authorization: Bearer $T1" "http://$API/api/notes")
want "list has title" '"title":"Shopping"' "$L"
printf '%s' "$L" | grep -q '"body"' && bad "list leaks body" || ok "list omits body"
want "update" '"title":"Shopping list"' "$(curl -s -H "authorization: Bearer $T1" -X PUT "http://$API/api/notes/$NID" -d '{"title":"Shopping list","body":"milk"}')"
want "malformed json -> 400" "invalid json" "$(curl -s -H "authorization: Bearer $T1" -X POST "http://$API/api/notes" --data-binary '{bad')"

echo "== per-user isolation =="
want "n2 sees no notes" '"notes":[]' "$(curl -s -H "authorization: Bearer $T2" "http://$API/api/notes")"
want "n2 cannot read n1 note" "not found" "$(curl -s -H "authorization: Bearer $T2" "http://$API/api/notes/$NID")"
want "n2 cannot delete n1 note" "not found" "$(curl -s -H "authorization: Bearer $T2" -X DELETE "http://$API/api/notes/$NID")"

echo "== delete =="
want "delete ok" '"ok":true' "$(curl -s -H "authorization: Bearer $T1" -X DELETE "http://$API/api/notes/$NID")"
want "get after delete -> 404" "not found" "$(curl -s -H "authorization: Bearer $T1" "http://$API/api/notes/$NID")"

finish
