#!/usr/bin/env bash
# Admin account lifecycle: suspend (see test_admin.sh), and the destructive trio —
# "backup + remove data" (the ACCOUNT STAYS), "restore", and "wipe" — including
# every failure mode.
source "$(dirname "$0")/lib.sh"
start_server 8106 || exit 1

# Point backups inside the throwaway dir, then restart so the server sees it.
kill "$SRV_PID" 2>/dev/null; wait "$SRV_PID" 2>/dev/null
echo "BACKUP_DIR=$TESTDIR/backups" >> "$TESTDIR/config.env"
echo "APPEAL_CONTACT=appeals@example.test" >> "$TESTDIR/config.env"
launch_server || exit 1
BK="$TESTDIR/backups"; ST="$TESTDIR/storage"

dbcount() { python3 -c "import sqlite3,sys; c=sqlite3.connect('$TESTDIR/cloud.db'); print(c.execute(sys.argv[1]).fetchone()[0])" "$1"; }
dbexec()  { python3 -c "import sqlite3,sys; c=sqlite3.connect('$TESTDIR/cloud.db'); c.execute(sys.argv[1]); c.commit()" "$1"; }
adm() { curl -s -H "authorization: Bearer $T1" "$@"; }
reg() { curl -s "http://$API/api/auth/register" -d "{\"email\":\"$1\",\"password\":\"supersecret\",\"inviteCode\":\"test-invite\",\"salt\":\"aabbccddeeff00112233445566778899\",\"wrappedDek\":\"WRAP1.DEK1\",\"wrappedDekRecovery\":\"WRAP2.DEK2\"}"; }
login() { curl -s "http://$API/api/auth/login" -d "{\"email\":\"$1\",\"password\":\"supersecret\"}"; }
ids_of() { grep -o '"id":[0-9]*' | sort | tr '\n' ' '; }

R1=$(reg a1@e.cc); T1=$(tok_of "$R1"); U1=$(id_of "$R1")
R2=$(reg v2@e.cc); T2=$(tok_of "$R2"); U2=$(id_of "$R2")
R3=$(reg o3@e.cc); T3=$(tok_of "$R3"); U3=$(id_of "$R3")

# Victim (v2): 2 files, a folder, a legacy note + an encrypted note, an API key.
curl -s -H "authorization: Bearer $T2" -H "X-Filename: doc1.txt" -X POST "http://$API/api/files" --data-binary "hello-one" >/dev/null
curl -s -H "authorization: Bearer $T2" -H "X-Filename: doc2.txt" -X POST "http://$API/api/files" --data-binary "hello-two-longer" >/dev/null
FOLDER=$(curl -s -H "authorization: Bearer $T2" -X POST "http://$API/api/folders" -d '{"name":"Docs"}'); FID=$(id_of "$FOLDER")
curl -s -H "authorization: Bearer $T2" -X POST "http://$API/api/notes" -d '{"title":"plain note","body":"legacy body"}' >/dev/null
curl -s -H "authorization: Bearer $T2" -X POST "http://$API/api/notes" -d '{"encTitle":"QUJDREVGRw==.QUJD","encBody":"WFla.QUJDREVGR0g="}' >/dev/null
AK=$(curl -s -H "authorization: Bearer $T2" -X POST "http://$API/api/auth/api-keys" -d '{"name":"k"}'); KEY=$(printf '%s' "$AK" | grep -o '"key":"csk_[a-f0-9]*' | cut -d'"' -f4)
# Bystander (o3): one file.
curl -s -H "authorization: Bearer $T3" -H "X-Filename: mine.txt" -X POST "http://$API/api/files" --data-binary "bystander-data" >/dev/null

FILES_BEFORE=$(curl -s -H "authorization: Bearer $T2" "http://$API/api/files" | ids_of)
NOTES_BEFORE=$(curl -s -H "authorization: Bearer $T2" "http://$API/api/notes" | ids_of)
BEFORE_HASHES=$(sha256sum "$ST/$U2"/* | awk '{print $1}' | sort)
want "victim has 2 blobs on disk before removal" "2" "$(ls "$ST/$U2" | wc -l)"
want "victim's API key works before removal" '"files"' "$(curl -s -H "X-API-Key: $KEY" "http://$API/api/files")"

echo "== guards =="
want "cannot remove yourself" "cannot remove or wipe your own account" "$(adm -X POST "http://$API/api/admin/users/$U1/remove")"
want "cannot wipe yourself" "cannot remove or wipe your own account" "$(adm -X POST "http://$API/api/admin/users/$U1/wipe" -d '{"confirmEmail":"a1@e.cc"}')"
want "non-admin cannot remove" "admin only" "$(curl -s -H "authorization: Bearer $T2" -X POST "http://$API/api/admin/users/$U3/remove")"
want "non-admin cannot restore" "admin only" "$(curl -s -H "authorization: Bearer $T2" -X POST "http://$API/api/admin/users/$U3/restore")"
want "non-admin cannot wipe" "admin only" "$(curl -s -H "authorization: Bearer $T2" -X POST "http://$API/api/admin/users/$U3/wipe" -d '{"confirmEmail":"o3@e.cc"}')"
want "non-admin cannot list removed users" "admin only" "$(curl -s -H "authorization: Bearer $T2" "http://$API/api/admin/removed-users")"
want "unauthenticated remove -> 401" "unauthorized" "$(curl -s -X POST "http://$API/api/admin/users/$U2/remove")"
want "unauthenticated restore -> 401" "unauthorized" "$(curl -s -X POST "http://$API/api/admin/users/$U2/restore")"
want "remove unknown user -> 404" "user not found" "$(adm -X POST "http://$API/api/admin/users/9999/remove")"
want "restore unknown user -> 404" "user not found" "$(adm -X POST "http://$API/api/admin/users/9999/restore")"
want "API key cannot remove (session only)" "unauthorized" "$(curl -s -H "X-API-Key: $KEY" -X POST "http://$API/api/admin/users/$U3/remove")"
want "cannot restore an account that isn't removed" "account is not removed" "$(adm -X POST "http://$API/api/admin/users/$U2/restore")"
want "reason must be a string" "reason must be a string" "$(adm -X POST "http://$API/api/admin/users/$U2/remove" -d '{"reason":5}')"
want "reason too long is refused" "reason is too long" "$(adm -X POST "http://$API/api/admin/users/$U2/remove" -d "{\"reason\":\"$(head -c 501 /dev/zero | tr '\0' 'x')\"}")"
want "reason with control characters is refused" "control characters" "$(adm -X POST "http://$API/api/admin/users/$U2/remove" -d '{"reason":"bad\u0001char"}')"
want "victim untouched after all the refusals" '"status":"active"' "$(adm "http://$API/api/admin/users" | grep -o "\"id\":$U2[^{}]*")"
[ "$(ls "$ST/$U2" | wc -l)" = "2" ] && ok "victim's blobs untouched by the refusals" || bad "a refused request changed the victim's storage"

echo "== backup + remove: the ACCOUNT STAYS, its data goes =="
RM=$(adm -X POST "http://$API/api/admin/users/$U2/remove" -d '{"reason":"Reported for abuse (test)"}')
want "remove succeeds" '"status":"removed"' "$RM"
want "reports the removed id" "\"removedUserId\":$U2" "$RM"
printf '%s' "$RM" | grep -q "backups" && bad "remove response leaks a filesystem path" || ok "remove response leaks no filesystem path"

want "the account still exists, now marked removed" '"status":"removed"' "$(adm "http://$API/api/admin/users" | grep -o "\"id\":$U2[^{}]*")"
want "a removed account uses no storage" '"storageUsedBytes":0' "$(adm "http://$API/api/admin/users" | grep -o "\"id\":$U2[^{}]*")"
want "its credentials + E2E key material are kept (kdf salt)" "aabbccddeeff00112233445566778899" "$(python3 -c "import sqlite3;print(sqlite3.connect('$TESTDIR/cloud.db').execute('select kdf_salt from users where id=$U2').fetchone()[0])")"
want "its wrapped DEK is kept" "WRAP1.DEK1" "$(python3 -c "import sqlite3;print(sqlite3.connect('$TESTDIR/cloud.db').execute('select wrapped_dek from users where id=$U2').fetchone()[0])")"
want "its recovery-wrapped DEK is kept" "WRAP2.DEK2" "$(python3 -c "import sqlite3;print(sqlite3.connect('$TESTDIR/cloud.db').execute('select wrapped_dek_recovery from users where id=$U2').fetchone()[0])")"

echo "== what the removed user sees at sign-in =="
LR=$(curl -s -D "$TESTDIR/h" "http://$API/api/auth/login" -d '{"email":"v2@e.cc","password":"supersecret"}')
want "login is refused with 403" "403" "$(head -1 "$TESTDIR/h")"
want "machine-readable code" '"code":"data_removed"' "$LR"
want "the default notice says data was temporarily removed and to appeal" "temporarily removed" "$LR"
want "the notice tells them to appeal" "please appeal" "$LR"
want "the admin's reason is shown" "Reported for abuse (test)" "$LR"
want "the configured appeal contact is shown" "appeals@example.test" "$LR"
printf '%s' "$LR" | grep -q '"token"' && bad "a removed account was issued a session token" || ok "no session token issued"
grep -qi '^set-cookie' "$TESTDIR/h" && bad "a removed account was issued a cookie" || ok "no session cookie issued"
want "a wrong password still just says invalid credentials (no status leak)" "invalid credentials" "$(curl -s "http://$API/api/auth/login" -d '{"email":"v2@e.cc","password":"wrongpassword"}')"
want "the old session is dead" "unauthorized" "$(curl -s -H "authorization: Bearer $T2" "http://$API/api/auth/me")"
want "the account's API key is dead too" "unauthorized" "$(curl -s -H "X-API-Key: $KEY" "http://$API/api/files")"

echo "== the backup =="
[ ! -e "$ST/$U2" ] && ok "live storage directory removed" || bad "live storage directory still exists"
BDIR=$(ls -d "$BK/${U2}_"* 2>/dev/null | head -1)
[ -d "$BDIR" ] && ok "backup directory created" || bad "no backup directory"
want "backup dir is owner-only (700)" "700" "$(stat -c %a "$BDIR" 2>/dev/null)"
want "backup data.json is owner-only (600)" "600" "$(stat -c %a "$BDIR/data.json" 2>/dev/null)"
DJ=$(cat "$BDIR/data.json" 2>/dev/null)
want "data.json has the account row" '"email": "v2@e.cc"' "$DJ"
want "data.json has the folder" '"Docs"' "$DJ"
want "data.json has the legacy note" '"plain note"' "$DJ"
want "data.json has the encrypted note's ciphertext" 'QUJDREVGRw==.QUJD' "$DJ"
want "data.json has both file rows" "2" "$(python3 -c "import json;print(len(json.load(open('$BDIR/data.json'))['files']))")"
AFTER_HASHES=$(sha256sum "$BDIR/storage"/* 2>/dev/null | awk '{print $1}' | sort)
[ -n "$AFTER_HASHES" ] && [ "$BEFORE_HASHES" = "$AFTER_HASHES" ] && ok "backed-up blobs are byte-identical to the originals" || bad "backup blobs differ from originals"
for t in files folders notes sessions upload_sessions; do
  want "no live $t rows remain" "0" "$(dbcount "SELECT COUNT(*) FROM $t WHERE user_id=$U2")"
done
want "the API key row is kept (inert until restore)" "1" "$(dbcount "SELECT COUNT(*) FROM api_keys WHERE user_id=$U2")"

want "bystander's files unaffected" "mine.txt" "$(curl -s -H "authorization: Bearer $T3" "http://$API/api/files")"
[ "$(ls "$ST/$U3" | wc -l)" = "1" ] && ok "bystander's blob untouched on disk" || bad "bystander's storage changed"

RL=$(adm "http://$API/api/admin/removed-users")
want "removed-users lists the account" '"email":"v2@e.cc"' "$RL"
want "removed-users records who removed it" "\"removedBy\":$U1" "$RL"
want "removed-users shows the reason" "Reported for abuse (test)" "$RL"
# The backup's footprint = the 25 bytes of blobs PLUS data.json, so strictly more than the blobs alone.
BB=$(printf '%s' "$RL" | grep -o '"backupBytes":[0-9]*' | cut -d: -f2)
[ -n "$BB" ] && [ "$BB" -gt 25 ] && [ "$BB" = "$(du -sb "$BDIR" | cut -f1 | python3 -c "import sys,os;t=0
for r,d,f in os.walk('$BDIR'):
  for x in f: t+=os.path.getsize(os.path.join(r,x))
print(t)")" ] && ok "removed-users reports the backup's real size on disk ($BB bytes)" || bad "backupBytes wrong: '$BB'"
printf '%s' "$RL" | grep -q "/backups\|backup_path" && bad "removed-users leaks the backup path" || ok "removed-users exposes no backup path"

echo "== a removed account cannot be quietly reactivated =="
want "remove again is refused" "already removed" "$(adm -X POST "http://$API/api/admin/users/$U2/remove")"
want "suspend toggle can't touch a removed account (unsuspend)" "account is removed" "$(adm -X PATCH "http://$API/api/admin/users/$U2" -d '{"suspended":false}')"
want "suspend toggle can't touch a removed account (suspend)" "account is removed" "$(adm -X PATCH "http://$API/api/admin/users/$U2" -d '{"suspended":true}')"
want "still removed after those attempts" '"code":"data_removed"' "$(login v2@e.cc)"

echo "== restore =="
RS=$(adm -X POST "http://$API/api/admin/users/$U2/restore")
want "restore succeeds" '"status":"active"' "$RS"
want "restore reports 2 files" '"files":2' "$RS"
want "restore reports 1 folder" '"folders":1' "$RS"
want "restore reports 2 notes" '"notes":2' "$RS"
NEWLOGIN=$(login v2@e.cc); T2=$(tok_of "$NEWLOGIN")
want "the owner can sign in again" '"token"' "$NEWLOGIN"
want "sign-in returns the same wrapped DEK, so their key still unlocks it" "WRAP1.DEK1" "$NEWLOGIN"
[ "$(curl -s -H "authorization: Bearer $T2" "http://$API/api/files" | ids_of)" = "$FILES_BEFORE" ] && ok "every file came back with its ORIGINAL id" || bad "file ids changed by the restore"
[ "$(curl -s -H "authorization: Bearer $T2" "http://$API/api/notes" | ids_of)" = "$NOTES_BEFORE" ] && ok "every note came back with its ORIGINAL id" || bad "note ids changed by the restore"
want "the folder came back (same id)" "\"id\":$FID" "$(curl -s -H "authorization: Bearer $T2" "http://$API/api/fs?folder=0")"
want "the encrypted note's ciphertext is byte-identical" 'QUJDREVGRw==.QUJD' "$(curl -s -H "authorization: Bearer $T2" "http://$API/api/notes")"
want "the legacy note came back" "plain note" "$(curl -s -H "authorization: Bearer $T2" "http://$API/api/notes")"
FIRST=$(curl -s -H "authorization: Bearer $T2" "http://$API/api/files" | grep -o '"id":[0-9]*' | head -1 | cut -d: -f2)
want "a restored file downloads with its exact original bytes" "hello" "$(curl -s -H "authorization: Bearer $T2" "http://$API/api/files/$FIRST")"
RESTORED_HASHES=$(sha256sum "$ST/$U2"/* | awk '{print $1}' | sort)
[ "$BEFORE_HASHES" = "$RESTORED_HASHES" ] && ok "live blobs are byte-identical to the originals" || bad "restored blobs differ"
[ ! -e "$BDIR" ] && ok "the backup was consumed (deleted) by the restore" || bad "backup left behind after restore"
want "the removal record is gone" "0" "$(dbcount "SELECT COUNT(*) FROM removed_users WHERE original_user_id=$U2")"
printf '%s' "$(adm "http://$API/api/admin/removed-users")" | grep -q '"email":"v2@e.cc"' && bad "still listed as removed" || ok "no longer listed as removed"
want "storage usage is back" '"storageUsedBytes":25' "$(adm "http://$API/api/admin/users" | grep -o "\"id\":$U2[^{}]*")"
want "the account's API key works again" '"files"' "$(curl -s -H "X-API-Key: $KEY" "http://$API/api/files")"
want "restore again is refused (nothing to restore)" "account is not removed" "$(adm -X POST "http://$API/api/admin/users/$U2/restore")"
NEWF=$(curl -s -H "authorization: Bearer $T2" -H "X-Filename: after.txt" -X POST "http://$API/api/files" --data-binary "after-restore")
[ "$(id_of "$NEWF")" -gt "$(echo "$FILES_BEFORE" | grep -o '[0-9]*' | sort -n | tail -1)" ] && ok "new uploads after a restore get fresh ids (no collision)" || bad "id collision after restore"

echo "== remove -> restore -> remove -> restore is repeatable =="
adm -X POST "http://$API/api/admin/users/$U2/remove" >/dev/null
want "second removal works" "removed" "$(adm "http://$API/api/admin/users" | grep -o "\"id\":$U2[^{}]*")"
want "second restore works" '"status":"active"' "$(adm -X POST "http://$API/api/admin/users/$U2/restore")"
want "all three files are present after the second cycle" "3" "$(curl -s -H "authorization: Bearer $(tok_of "$(login v2@e.cc)")" "http://$API/api/files" | grep -o '"id":' | wc -l)"

echo "== restore refuses a bad backup and changes nothing =="
adm -X POST "http://$API/api/admin/users/$U2/remove" >/dev/null
BDIR=$(ls -d "$BK/${U2}_"* | head -1)
CANARY="$TESTDIR/outside"; mkdir -p "$CANARY"; echo keep > "$CANARY/canary.txt"
still_removed() { want "$1" '"code":"data_removed"' "$(login v2@e.cc)"; [ ! -e "$ST/$U2" ] || [ -z "$(ls -A "$ST/$U2" 2>/dev/null)" ] && ok "  ...and no blobs were left in the live store" || bad "  ...blobs left in the live store"; }

cp "$BDIR/data.json" "$TESTDIR/data.good"
# (a) a backup of a DIFFERENT account
python3 -c "import json;d=json.load(open('$BDIR/data.json'));d['user']['id']=999;json.dump(d,open('$BDIR/data.json','w'))"
want "a backup that belongs to another account is refused" "different account" "$(adm -X POST "http://$API/api/admin/users/$U2/restore")"
still_removed "account still removed after the foreign-backup attempt"
cp "$TESTDIR/data.good" "$BDIR/data.json"
# (b) corrupt data.json
echo "{not json" > "$BDIR/data.json"
want "a corrupt data.json is refused" "not a valid backup" "$(adm -X POST "http://$API/api/admin/users/$U2/restore")"
still_removed "account still removed after the corrupt-backup attempt"
cp "$TESTDIR/data.good" "$BDIR/data.json"
# (c) an unsafe storage key
python3 -c "import json;d=json.load(open('$BDIR/data.json'));d['files'][0]['storage_key']='../../etc/passwd';json.dump(d,open('$BDIR/data.json','w'))"
want "an unsafe storage key is refused" "unsafe storage key" "$(adm -X POST "http://$API/api/admin/users/$U2/restore")"
still_removed "account still removed after the unsafe-key attempt"
cp "$TESTDIR/data.good" "$BDIR/data.json"
# (d) an incomplete backup (a blob missing)
VICTIM_BLOB=$(ls "$BDIR/storage" | head -1); mv "$BDIR/storage/$VICTIM_BLOB" "$TESTDIR/blob.held"
want "an incomplete backup is refused" "backup is incomplete" "$(adm -X POST "http://$API/api/admin/users/$U2/restore")"
still_removed "account still removed after the incomplete-backup attempt"
mv "$TESTDIR/blob.held" "$BDIR/storage/$VICTIM_BLOB"
# (e) column-name injection through data.json keys must be ignored, not executed
python3 -c "import json;d=json.load(open('$BDIR/data.json'));d['folders'][0]['zz); DROP TABLE notes;--']=1;json.dump(d,open('$BDIR/data.json','w'))"
NOTES_TABLE_BEFORE=$(dbcount "SELECT COUNT(*) FROM sqlite_master WHERE name='notes'")
want "a data.json with a malicious column name still restores (unknown columns ignored)" '"status":"active"' "$(adm -X POST "http://$API/api/admin/users/$U2/restore")"
want "...and the notes table was NOT dropped" "$NOTES_TABLE_BEFORE" "$(dbcount "SELECT COUNT(*) FROM sqlite_master WHERE name='notes'")"

echo "== a failure part-way through restore rolls everything back =="
adm -X POST "http://$API/api/admin/users/$U2/remove" >/dev/null
BDIR=$(ls -d "$BK/${U2}_"* | head -1)
dbexec "CREATE TRIGGER block_file_insert BEFORE INSERT ON files BEGIN SELECT RAISE(ABORT,'blocked by test'); END"
FR=$(adm -X POST "http://$API/api/admin/users/$U2/restore")
want "restore reports the failure" "nothing was changed" "$FR"
still_removed "account still removed after the failed restore"
[ -d "$BDIR" ] && [ -f "$BDIR/data.json" ] && ok "the backup is intact after the failed restore" || bad "the failed restore damaged the backup"
want "no rows were left behind by the rolled-back restore" "0" "$(dbcount "SELECT COUNT(*) FROM folders WHERE user_id=$U2")"
want "the removal record is still there" "1" "$(dbcount "SELECT COUNT(*) FROM removed_users WHERE original_user_id=$U2")"
dbexec "DROP TRIGGER block_file_insert"
want "once the fault is cleared the same restore succeeds" '"status":"active"' "$(adm -X POST "http://$API/api/admin/users/$U2/restore")"

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
want "wiped account's row is gone" "0" "$(dbcount "SELECT COUNT(*) FROM users WHERE id=$U4")"
want "wiped account's files are gone" "0" "$(dbcount "SELECT COUNT(*) FROM files WHERE user_id=$U4")"
[ "$(ls "$BK" | wc -l)" = "$BACKUPS_BEFORE" ] && ok "wiping a live account created no backup" || bad "wipe left a backup behind"
want "wiped account cannot log in" "invalid credentials" "$(login w4@e.cc)"

echo "== wipe a REMOVED account (also deletes its backup) =="
R5=$(reg x5@e.cc); T5=$(tok_of "$R5"); U5=$(id_of "$R5")
curl -s -H "authorization: Bearer $T5" -H "X-Filename: x.txt" -X POST "http://$API/api/files" --data-binary "x5-data" >/dev/null
adm -X POST "http://$API/api/admin/users/$U5/remove" >/dev/null
B5=$(ls -d "$BK/${U5}_"* | head -1)
want "wiping a removed account still needs confirmEmail" "confirmEmail must exactly match" "$(adm -X POST "http://$API/api/admin/users/$U5/wipe" -d '{"confirmEmail":"nope@e.cc"}')"
[ -d "$B5" ] && ok "backup survives a refused wipe" || bad "refused wipe deleted the backup"
W5=$(adm -X POST "http://$API/api/admin/users/$U5/wipe" -d '{"confirmEmail":"x5@e.cc"}')
want "wipe of a removed account succeeds" '"wiped":true' "$W5"
want "...and reports its backup was deleted" '"backupRemoved":true' "$W5"
[ ! -e "$B5" ] && ok "the backup bundle is gone from disk" || bad "backup bundle still on disk"
want "the account row is gone" "0" "$(dbcount "SELECT COUNT(*) FROM users WHERE id=$U5")"
want "the removal record is gone" "0" "$(dbcount "SELECT COUNT(*) FROM removed_users WHERE original_user_id=$U5")"
want "it can no longer log in at all" "invalid credentials" "$(login x5@e.cc)"

echo "== path safety: a tampered removal record must never delete outside the backup root =="
R6=$(reg t6@e.cc); U6=$(id_of "$R6")
adm -X POST "http://$API/api/admin/users/$U6/remove" >/dev/null
B6=$(ls -d "$BK/${U6}_"* | head -1)
for evil in "$CANARY" "$BK" "$TESTDIR" "$BK/../outside" "/"; do
  dbexec "UPDATE removed_users SET backup_path='$evil' WHERE original_user_id=$U6"
  want "wipe refuses tampered path '$evil'" "refusing to delete" "$(adm -X POST "http://$API/api/admin/users/$U6/wipe" -d '{"confirmEmail":"t6@e.cc"}')"
  want "restore refuses tampered path '$evil'" "outside the backup directory" "$(adm -X POST "http://$API/api/admin/users/$U6/restore")"
done
[ -f "$CANARY/canary.txt" ] && ok "canary outside the backup root survived every tampered attempt" || bad "a tampered request deleted files outside the backup root"
[ -d "$BK" ] && [ -d "$TESTDIR" ] && ok "backup root itself survived" || bad "backup root was deleted"
want "the account was NOT deleted by the refused wipes" "1" "$(dbcount "SELECT COUNT(*) FROM users WHERE id=$U6")"
dbexec "UPDATE removed_users SET backup_path='$B6' WHERE original_user_id=$U6"
want "with the record repaired, the wipe works" '"wiped":true' "$(adm -X POST "http://$API/api/admin/users/$U6/wipe" -d '{"confirmEmail":"t6@e.cc"}')"

echo "== a removed account whose backup was deleted by hand can still be wiped =="
R7=$(reg h7@e.cc); U7=$(id_of "$R7")
adm -X POST "http://$API/api/admin/users/$U7/remove" >/dev/null
rm -rf "$BK/${U7}_"*
want "restore of a vanished backup fails safely" "missing" "$(adm -X POST "http://$API/api/admin/users/$U7/restore")"
want "wipe still works" '"wiped":true' "$(adm -X POST "http://$API/api/admin/users/$U7/wipe" -d '{"confirmEmail":"h7@e.cc"}')"

echo "== failure part-way through remove leaves the live account fully intact =="
R8=$(reg f8@e.cc); T8=$(tok_of "$R8"); U8=$(id_of "$R8")
curl -s -H "authorization: Bearer $T8" -H "X-Filename: keep.txt" -X POST "http://$API/api/files" --data-binary "must-survive" >/dev/null
dbexec "CREATE TRIGGER block_status BEFORE UPDATE OF status ON users WHEN NEW.status='removed' BEGIN SELECT RAISE(ABORT,'blocked by test'); END"
FR8=$(adm -X POST "http://$API/api/admin/users/$U8/remove")
want "remove reports failure" "nothing was changed" "$FR8"
want "the account is still active" '"token"' "$(login f8@e.cc)"
want "its files are intact" "keep.txt" "$(curl -s -H "authorization: Bearer $T8" "http://$API/api/files")"
[ "$(ls "$ST/$U8" 2>/dev/null | wc -l)" = "1" ] && ok "live blob untouched" || bad "live blob missing"
want "the removal record was rolled back too" "0" "$(dbcount "SELECT COUNT(*) FROM removed_users WHERE original_user_id=$U8")"
[ -z "$(ls "$BK" | grep "^${U8}_")" ] && ok "the already-written backup was cleaned up" || bad "partial backup left behind"
dbexec "DROP TRIGGER block_status"
want "once the fault is cleared the same remove succeeds" '"status":"removed"' "$(adm -X POST "http://$API/api/admin/users/$U8/remove")"

echo "== early failure (backup root unusable) also leaves the account intact =="
R9=$(reg e9@e.cc); T9=$(tok_of "$R9"); U9=$(id_of "$R9")
curl -s -H "authorization: Bearer $T9" -H "X-Filename: keep9.txt" -X POST "http://$API/api/files" --data-binary "still-here" >/dev/null
mv "$BK" "$TESTDIR/backups.real"; : > "$BK"
FR9=$(adm -X POST "http://$API/api/admin/users/$U9/remove")
rm -f "$BK"; mv "$TESTDIR/backups.real" "$BK"
want "remove reports failure" "could not" "$FR9"
want "the account is still active with its files" "keep9.txt" "$(curl -s -H "authorization: Bearer $T9" "http://$API/api/files")"

echo "== \"last admin\" only counts admins who can actually act =="
adm -X PATCH "http://$API/api/admin/users/$U3" -d '{"role":"admin"}' >/dev/null     # o3 becomes a second admin
want "suspend the second admin (a1 remains active)" '"status":"suspended"' "$(adm -X PATCH "http://$API/api/admin/users/$U3" -d '{"suspended":true}')"
want "a1 can no longer demote itself: the other admin is suspended, so it is the last ACTIVE one" "cannot remove the last admin" "$(adm -X PATCH "http://$API/api/admin/users/$U1" -d '{"role":"user"}')"
want "a suspended admin CAN be removed (it doesn't reduce the active admins)" '"status":"removed"' "$(adm -X POST "http://$API/api/admin/users/$U3/remove")"
want "restoring it returns it to service" '"status":"active"' "$(adm -X POST "http://$API/api/admin/users/$U3/restore")"
want "sole active admin still cannot remove themselves" "cannot remove or wipe your own account" "$(adm -X POST "http://$API/api/admin/users/$U1/remove")"

finish
