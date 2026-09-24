#!/usr/bin/env bash
# Admin account lifecycle: suspend is covered in test_admin.sh; this covers the
# destructive pair — "backup + remove" and "wipe" — including the failure modes.
source "$(dirname "$0")/lib.sh"
start_server 8106 || exit 1

# Point backups inside the throwaway dir, then restart so the server sees it.
kill "$SRV_PID" 2>/dev/null; wait "$SRV_PID" 2>/dev/null
echo "BACKUP_DIR=$TESTDIR/backups" >> "$TESTDIR/config.env"
launch_server || exit 1
BK="$TESTDIR/backups"; ST="$TESTDIR/storage"

# dbcount "<sql returning one number>"
dbcount() { python3 -c "import sqlite3,sys; c=sqlite3.connect('$TESTDIR/cloud.db'); print(c.execute(sys.argv[1]).fetchone()[0])" "$1"; }
adm() { curl -s -H "authorization: Bearer $T1" "$@"; }   # admin-authenticated curl
reg() { curl -s "http://$API/api/auth/register" -d "{\"email\":\"$1\",\"password\":\"supersecret\",\"inviteCode\":\"test-invite\"}"; }

R1=$(reg a1@e.cc); T1=$(tok_of "$R1"); U1=$(id_of "$R1")
R2=$(reg v2@e.cc); T2=$(tok_of "$R2"); U2=$(id_of "$R2")
R3=$(reg o3@e.cc); T3=$(tok_of "$R3"); U3=$(id_of "$R3")

# Victim (v2) owns 2 files, a folder and a note. Bystander (o3) owns 1 file.
curl -s -H "authorization: Bearer $T2" -H "X-Filename: doc1.txt" -X POST "http://$API/api/files" --data-binary "hello-one" >/dev/null
curl -s -H "authorization: Bearer $T2" -H "X-Filename: doc2.txt" -X POST "http://$API/api/files" --data-binary "hello-two-longer" >/dev/null
curl -s -H "authorization: Bearer $T2" -X POST "http://$API/api/folders" -d '{"name":"Docs"}' >/dev/null
curl -s -H "authorization: Bearer $T2" -X POST "http://$API/api/notes" -d '{"title":"secret note","body":"note body text"}' >/dev/null
curl -s -H "authorization: Bearer $T3" -H "X-Filename: mine.txt" -X POST "http://$API/api/files" --data-binary "bystander-data" >/dev/null

BEFORE_HASHES=$(sha256sum "$ST/$U2"/* | awk '{print $1}' | sort)
want "victim has 2 blobs on disk before removal" "2" "$(ls "$ST/$U2" | wc -l)"

echo "== guards =="
want "cannot remove yourself" "cannot remove or wipe your own account" "$(adm -X POST "http://$API/api/admin/users/$U1/remove")"
want "cannot wipe yourself" "cannot remove or wipe your own account" "$(adm -X POST "http://$API/api/admin/users/$U1/wipe" -d '{"confirmEmail":"a1@e.cc"}')"
want "non-admin cannot remove" "admin only" "$(curl -s -H "authorization: Bearer $T2" -X POST "http://$API/api/admin/users/$U3/remove")"
want "non-admin cannot wipe" "admin only" "$(curl -s -H "authorization: Bearer $T2" -X POST "http://$API/api/admin/users/$U3/wipe" -d '{"confirmEmail":"o3@e.cc"}')"
want "non-admin cannot list removed users" "admin only" "$(curl -s -H "authorization: Bearer $T2" "http://$API/api/admin/removed-users")"
want "unauthenticated remove -> 401" "unauthorized" "$(curl -s -X POST "http://$API/api/admin/users/$U2/remove")"
want "remove unknown user -> 404" "user not found" "$(adm -X POST "http://$API/api/admin/users/9999/remove")"
want "API key cannot remove (session only)" "unauthorized" "$(curl -s -H "X-API-Key: csk_nope" -X POST "http://$API/api/admin/users/$U2/remove")"
want "victim untouched after all the refusals" "\"email\":\"v2@e.cc\"" "$(adm "http://$API/api/admin/users")"

echo "== backup + remove =="
RM=$(adm -X POST "http://$API/api/admin/users/$U2/remove")
want "remove succeeds" '"tombstoneId"' "$RM"
want "reports the removed id" "\"removedUserId\":$U2" "$RM"
TID=$(printf '%s' "$RM" | grep -o '"tombstoneId":[0-9]*' | cut -d: -f2)
printf '%s' "$RM" | grep -q "backups" && bad "remove response leaks a filesystem path" || ok "remove response leaks no filesystem path"

want "victim's session is dead" "unauthorized" "$(curl -s -H "authorization: Bearer $T2" "http://$API/api/auth/me")"
want "victim cannot log in (account is gone)" "invalid credentials" "$(curl -s "http://$API/api/auth/login" -d '{"email":"v2@e.cc","password":"supersecret"}')"
[ ! -e "$ST/$U2" ] && ok "live storage directory removed" || bad "live storage directory still exists"
printf '%s' "$(adm "http://$API/api/admin/users")" | grep -q '"email":"v2@e.cc"' && bad "victim still listed as a live user" || ok "victim no longer a live user"

BDIR=$(ls -d "$BK/${U2}_"* 2>/dev/null | head -1)
[ -d "$BDIR" ] && ok "backup directory created" || bad "no backup directory"
want "backup dir is owner-only (700)" "700" "$(stat -c %a "$BDIR" 2>/dev/null)"
want "backup data.json is owner-only (600)" "600" "$(stat -c %a "$BDIR/data.json" 2>/dev/null)"
DJ=$(cat "$BDIR/data.json" 2>/dev/null)
want "data.json has the account row" '"email": "v2@e.cc"' "$DJ"
want "data.json has the folder" '"Docs"' "$DJ"
want "data.json has the note" '"secret note"' "$DJ"
want "data.json has both file rows" "2" "$(python3 -c "import json;print(len(json.load(open('$BDIR/data.json'))['files']))")"
want "data.json records who removed it" "\"removedBy\": $U1" "$DJ"
AFTER_HASHES=$(sha256sum "$BDIR/storage"/* 2>/dev/null | awk '{print $1}' | sort)
[ -n "$AFTER_HASHES" ] && [ "$BEFORE_HASHES" = "$AFTER_HASHES" ] && ok "backed-up blobs are byte-identical to the originals" || bad "backup blobs differ from originals"

want "no orphan file rows" "0" "$(dbcount "SELECT COUNT(*) FROM files WHERE user_id=$U2")"
want "no orphan folder rows" "0" "$(dbcount "SELECT COUNT(*) FROM folders WHERE user_id=$U2")"
want "no orphan note rows" "0" "$(dbcount "SELECT COUNT(*) FROM notes WHERE user_id=$U2")"
want "no orphan session rows" "0" "$(dbcount "SELECT COUNT(*) FROM sessions WHERE user_id=$U2")"

want "bystander's files unaffected" "mine.txt" "$(curl -s -H "authorization: Bearer $T3" "http://$API/api/files")"
[ "$(ls "$ST/$U3" | wc -l)" = "1" ] && ok "bystander's blob untouched on disk" || bad "bystander's storage changed"

RL=$(adm "http://$API/api/admin/removed-users")
want "removed-users lists the tombstone" '"email":"v2@e.cc"' "$RL"
want "tombstone records who removed" "\"removedBy\":$U1" "$RL"
printf '%s' "$RL" | grep -q "backup" && bad "removed-users leaks the backup path" || ok "removed-users exposes no backup path"

NEW=$(reg v2@e.cc)
NEWID=$(id_of "$NEW")
[ -n "$NEWID" ] && [ "$NEWID" != "$U2" ] && ok "same email can re-register and gets a NEW id (ids never reused)" || bad "re-registered account reused id $U2"
[ ! -e "$ST/$U2" ] && ok "old storage dir not resurrected by the new account" || bad "new account inherited the old storage dir"

echo "== wipe a live account (no backup) =="
R4=$(reg w4@e.cc); T4=$(tok_of "$R4"); U4=$(id_of "$R4")
curl -s -H "authorization: Bearer $T4" -H "X-Filename: gone.txt" -X POST "http://$API/api/files" --data-binary "wipe-me" >/dev/null
BACKUPS_BEFORE=$(ls "$BK" | wc -l)
want "wipe without confirmEmail is refused" "confirmEmail must exactly match" "$(adm -X POST "http://$API/api/admin/users/$U4/wipe" -d '{}')"
want "wipe with the wrong confirmEmail is refused" "confirmEmail must exactly match" "$(adm -X POST "http://$API/api/admin/users/$U4/wipe" -d '{"confirmEmail":"someone@else.cc"}')"
want "wipe with a non-string confirmEmail is refused" "confirmEmail must exactly match" "$(adm -X POST "http://$API/api/admin/users/$U4/wipe" -d '{"confirmEmail":123}')"
[ -d "$ST/$U4" ] && ok "nothing deleted by the refused wipes" || bad "refused wipe still deleted storage"
WP=$(adm -X POST "http://$API/api/admin/users/$U4/wipe" -d '{"confirmEmail":"W4@E.cc"}')
want "wipe succeeds (email confirm is case-insensitive)" '"wiped":true' "$WP"
[ ! -e "$ST/$U4" ] && ok "wiped account's storage deleted" || bad "wiped account's storage remains"
want "wiped account's rows gone" "0" "$(dbcount "SELECT COUNT(*) FROM users WHERE id=$U4")"
want "wiped account's files gone" "0" "$(dbcount "SELECT COUNT(*) FROM files WHERE user_id=$U4")"
[ "$(ls "$BK" | wc -l)" = "$BACKUPS_BEFORE" ] && ok "wipe created no backup" || bad "wipe left a backup behind"
want "wiped account cannot log in" "invalid credentials" "$(curl -s "http://$API/api/auth/login" -d '{"email":"w4@e.cc","password":"supersecret"}')"
want "removed-users list unchanged by a live wipe" '"email":"v2@e.cc"' "$(adm "http://$API/api/admin/removed-users")"

echo "== wipe a removed account's backup =="
want "tombstone wipe with wrong confirm refused" "confirmEmail must exactly match" "$(adm -X POST "http://$API/api/admin/removed-users/$TID/wipe" -d '{"confirmEmail":"nope@e.cc"}')"
[ -d "$BDIR" ] && ok "backup survives a refused wipe" || bad "refused wipe deleted the backup"
want "unknown tombstone -> 404" "removed account not found" "$(adm -X POST "http://$API/api/admin/removed-users/9999/wipe" -d '{"confirmEmail":"x@e.cc"}')"
want "non-admin cannot wipe a backup" "admin only" "$(curl -s -H "authorization: Bearer $T3" -X POST "http://$API/api/admin/removed-users/$TID/wipe" -d '{"confirmEmail":"v2@e.cc"}')"
want "tombstone wipe succeeds" '"wiped":true' "$(adm -X POST "http://$API/api/admin/removed-users/$TID/wipe" -d '{"confirmEmail":"v2@e.cc"}')"
[ ! -e "$BDIR" ] && ok "backup bundle deleted from disk" || bad "backup bundle still on disk"
want "tombstone row gone" "0" "$(dbcount "SELECT COUNT(*) FROM removed_users WHERE id=$TID")"
printf '%s' "$(adm "http://$API/api/admin/removed-users")" | grep -q '"email":"v2@e.cc"' && bad "tombstone still listed" || ok "tombstone no longer listed"

echo "== path safety: a tampered tombstone must never delete outside the backup root =="
R5=$(reg x5@e.cc); U5=$(id_of "$R5")
RM5=$(adm -X POST "http://$API/api/admin/users/$U5/remove"); TID5=$(printf '%s' "$RM5" | grep -o '"tombstoneId":[0-9]*' | cut -d: -f2)
CANARY="$TESTDIR/outside"; mkdir -p "$CANARY"; echo keep > "$CANARY/canary.txt"
for evil in "$CANARY" "$BK" "$TESTDIR" "$BK/../outside" "/"; do
  python3 -c "import sqlite3;c=sqlite3.connect('$TESTDIR/cloud.db');c.execute('UPDATE removed_users SET backup_path=? WHERE id=$TID5',('$evil',));c.commit()"
  OUT=$(adm -X POST "http://$API/api/admin/removed-users/$TID5/wipe" -d '{"confirmEmail":"x5@e.cc"}')
  want "refuses tampered path '$evil'" "refusing to delete" "$OUT"
done
[ -f "$CANARY/canary.txt" ] && ok "canary outside the backup root survived every tampered wipe" || bad "a tampered wipe deleted files outside the backup root"
[ -d "$BK" ] && [ -d "$TESTDIR" ] && ok "backup root itself survived" || bad "backup root was deleted"

echo "== late failure (backup fully written, DB delete aborts) rolls everything back =="
R6=$(reg f6@e.cc); T6=$(tok_of "$R6"); U6=$(id_of "$R6")
curl -s -H "authorization: Bearer $T6" -H "X-Filename: keep.txt" -X POST "http://$API/api/files" --data-binary "must-survive" >/dev/null
python3 -c "import sqlite3;c=sqlite3.connect('$TESTDIR/cloud.db');c.execute(\"CREATE TRIGGER block_user_delete BEFORE DELETE ON users BEGIN SELECT RAISE(ABORT,'blocked by test'); END\");c.commit()"
FR=$(adm -X POST "http://$API/api/admin/users/$U6/remove")
want "remove reports failure" "nothing was changed" "$FR"
want "account still exists after the failed remove" "1" "$(dbcount "SELECT COUNT(*) FROM users WHERE id=$U6")"
want "account can still log in" '"token"' "$(curl -s "http://$API/api/auth/login" -d '{"email":"f6@e.cc","password":"supersecret"}')"
want "files still intact" "keep.txt" "$(curl -s -H "authorization: Bearer $T6" "http://$API/api/files")"
[ "$(ls "$ST/$U6" 2>/dev/null | wc -l)" = "1" ] && ok "live blob untouched by the failed remove" || bad "live blob missing after the failed remove"
want "the tombstone insert was rolled back too" "0" "$(dbcount "SELECT COUNT(*) FROM removed_users WHERE original_user_id=$U6")"
[ -z "$(ls "$BK" | grep "^${U6}_")" ] && ok "the already-written backup was cleaned up" || bad "partial backup left behind"
python3 -c "import sqlite3;c=sqlite3.connect('$TESTDIR/cloud.db');c.execute('DROP TRIGGER block_user_delete');c.commit()"
want "once the fault is cleared the same remove succeeds" '"tombstoneId"' "$(adm -X POST "http://$API/api/admin/users/$U6/remove")"

echo "== early failure (backup root unusable) also leaves the account intact =="
R7=$(reg f7@e.cc); T7=$(tok_of "$R7"); U7=$(id_of "$R7")
curl -s -H "authorization: Bearer $T7" -H "X-Filename: keep7.txt" -X POST "http://$API/api/files" --data-binary "must-survive-too" >/dev/null
mv "$BK" "$TESTDIR/backups.real"; : > "$BK"      # backup root is now a regular file
FR7=$(adm -X POST "http://$API/api/admin/users/$U7/remove")
rm -f "$BK"; mv "$TESTDIR/backups.real" "$BK"
want "remove reports failure" "could not" "$FR7"
want "account still exists" "1" "$(dbcount "SELECT COUNT(*) FROM users WHERE id=$U7")"
want "files still intact" "keep7.txt" "$(curl -s -H "authorization: Bearer $T7" "http://$API/api/files")"
[ "$(ls "$ST/$U7" 2>/dev/null | wc -l)" = "1" ] && ok "live blob untouched" || bad "live blob missing"

echo "== an admin can remove another admin, but the last one is protected by the self-block =="
adm -X PATCH "http://$API/api/admin/users/$U3" -d '{"role":"admin"}' >/dev/null
want "remove a second admin while another admin exists" '"tombstoneId"' "$(adm -X POST "http://$API/api/admin/users/$U3/remove")"
want "sole remaining admin still cannot remove themselves" "cannot remove or wipe your own account" "$(adm -X POST "http://$API/api/admin/users/$U1/remove")"

finish
