#!/usr/bin/env bash
# `cloud_serv admin create-admin`: the initial-admin CLI. Registration is CLOSED
# (no invite code) for this whole file: the admin exists without ever registering.
EXTRA_CONFIG="REGISTRATION_INVITE_CODE="
source "$(dirname "$0")/lib.sh"
start_server 8108 || exit 1
kill "$SRV_PID" 2>/dev/null; wait "$SRV_PID" 2>/dev/null     # the CLI works with the server DOWN...
CFG="$TESTDIR/config.env"; BIN="$ROOT/cloud_serv"
dbq() { python3 -c "import sqlite3,sys; print(sqlite3.connect('$TESTDIR/cloud.db').execute(sys.argv[1]).fetchone()[0])" "$1"; }
PW="correct horse battery staple"

echo "== creates a working admin =="
OUT=$(printf '%s\n' "$PW" | "$BIN" admin create-admin --email Boss@Example.CC --name "The Boss" --config "$CFG" --password-stdin --recovery-key-file "$TESTDIR/rec1" 2>&1); RC=$?
want "exits 0" "0" "$RC"
want "says it created the account" "Created admin account 'boss@example.cc'" "$OUT"
printf '%s' "$OUT" | grep -qF "$PW" && bad "the password was echoed" || ok "the password is never printed"
REC1=$(tr -d '\n' < "$TESTDIR/rec1")
printf '%s' "$OUT" | grep -qF "$REC1" && bad "the recovery key was printed although a file was requested" || ok "the recovery key goes to the file, not the terminal"
want "recovery key file is mode 600" "600" "$(stat -c %a "$TESTDIR/rec1")"
printf '%s' "$REC1" | grep -Eq '^csr_[A-Za-z0-9+/]{43}=$' && ok "recovery key has the documented format" || bad "recovery key format: $REC1"
want "email stored lowercase" "boss@example.cc" "$(dbq "select email from users")"
want "display name stored" "The Boss" "$(dbq "select display_name from users")"
want "role is admin" "admin" "$(dbq "select role from users")"
want "status is active" "active" "$(dbq "select status from users")"
printf '%s' "$(dbq "select kdf_salt from users")" | grep -Eq '^[0-9a-f]{32}$' && ok "kdf salt is 32 lowercase hex chars" || bad "kdf salt malformed"
printf '%s' "$(dbq "select wrapped_dek from users")" | grep -Eq '^[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=]+$' && ok "wrappedDek has the iv.ct form" || bad "wrappedDek malformed"
printf '%s' "$(dbq "select wrapped_dek_recovery from users")" | grep -Eq '^[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=]+$' && ok "wrappedDekRecovery has the iv.ct form" || bad "wrappedDekRecovery malformed"
want "server-side hash is stored, not the auth key" "pbkdf2$" "$(dbq "select password_hash from users")"
[ "$(cat "$TESTDIR"/cloud.db* | grep -c "$PW")" = "0" ] && ok "the password appears nowhere in the database files" || bad "PASSWORD FOUND IN THE DATABASE"

echo "== refusals leave nothing behind =="
OUT=$(printf '%s\n' "$PW" | "$BIN" admin create-admin --email boss@example.cc --config "$CFG" --password-stdin 2>&1); RC=$?
want "duplicate email refused (exit 1)" "1" "$RC"; want "...with a clear message" "already exists" "$OUT"
OUT=$(printf 'short\n' | "$BIN" admin create-admin --email s@example.cc --config "$CFG" --password-stdin 2>&1); RC=$?
want "short password refused (exit 1)" "1" "$RC"; want "...with a clear message" "at least 8" "$OUT"
OUT=$("$BIN" admin create-admin --email not-an-email --config "$CFG" --password-stdin <<< "$PW" 2>&1); RC=$?
want "invalid email refused (exit 1)" "1" "$RC"; want "...with a clear message" "not a valid email" "$OUT"
OUT=$("$BIN" admin create-admin --config "$CFG" --password-stdin <<< "$PW" 2>&1); RC=$?
want "missing --email is a usage error (exit 2)" "2" "$RC"
OUT=$("$BIN" admin create-admin --email p@example.cc --password hunter2hunter2 --config "$CFG" 2>&1); RC=$?
want "a password argument is refused (exit 2)" "2" "$RC"; want "...and it explains why" "visible in \`ps\`" "$OUT"
OUT=$("$BIN" admin create-admin --email t@example.cc --config "$CFG" < /dev/null 2>&1); RC=$?
want "no TTY and no --password-stdin: refused rather than reading silently" "1" "$RC"
want "...and it says how to script it" "--password-stdin" "$OUT"
OUT=$(printf '%s\n' "$PW" | "$BIN" admin create-admin --email k@example.cc --config "$CFG" --password-stdin --recovery-key-file "$TESTDIR/rec1" 2>&1); RC=$?
want "an existing recovery-key file is never overwritten (exit 1)" "1" "$RC"
want "...and no account is created when the key can't be saved" "no account was created" "$OUT"
[ "$(tr -d '\n' < "$TESTDIR/rec1")" = "$REC1" ] && ok "the existing recovery key file is untouched" || bad "an existing recovery key file was overwritten"
OUT=$(printf '%s\n' "$PW" | "$BIN" admin create-admin --email d@example.cc --config "$CFG" --password-stdin --recovery-key-file "$TESTDIR/no/such/dir/rec" 2>&1); RC=$?
want "an unwritable recovery-key path is refused (exit 1)" "1" "$RC"
want "after all the refusals there is still exactly one account" "1" "$(dbq "select count(*) from users")"
want "unknown admin command is a usage error (exit 2)" "2" "$("$BIN" admin frobnicate >/dev/null 2>&1; echo $?)"
want "'admin help' exits 0 and lists create-admin" "create-admin" "$("$BIN" admin help 2>&1)"
want "'admin' alone is a usage error (exit 2)" "2" "$("$BIN" admin >/dev/null 2>&1; echo $?)"

echo "== without a recovery-key file it prints the key once, and works while the server is UP =="
launch_server || exit 1
OUT2=$(printf '%s\n' "second password ok" | "$BIN" admin create-admin --email second@example.cc --config "$CFG" --password-stdin 2>&1); RC=$?
want "second admin created against a RUNNING server" "0" "$RC"
REC2=$(printf '%s' "$OUT2" | grep -Eo 'csr_[A-Za-z0-9+/]{43}=')
[ -n "$REC2" ] && ok "the recovery key is printed exactly once" || bad "no recovery key printed"
[ "$(printf '%s' "$OUT2" | grep -c "$REC2")" = "1" ] && ok "...and only once" || bad "recovery key printed more than once"
[ "$REC2" != "$REC1" ] && ok "two accounts get different recovery keys" || bad "recovery keys collide"
[ "$(dbq "select count(distinct kdf_salt) from users")" = "2" ] && ok "two accounts get different salts" || bad "salts collide"
[ "$(dbq "select count(distinct wrapped_dek) from users")" = "2" ] && ok "two accounts get different wrapped data keys" || bad "wrapped keys collide"
# An unknown email gets a DECOY salt; the real salt only comes back if the running server
# actually reads the row the CLI just wrote (so this can't pass by accident).
SALT2=$(dbq "select kdf_salt from users where email='second@example.cc'")
want "the running server serves the CLI-created account's real salt" "\"salt\":\"$SALT2\"" "$(curl -s "http://$API/api/auth/salt?email=second@example.cc")"
want "registration is closed (no invite code)" "registration is not open" "$(curl -s "http://$API/api/auth/register" -d '{"email":"r@example.cc","password":"supersecret"}')"

echo "== the account works in the REAL browser client =="
WREC=$(dbq "select wrapped_dek_recovery from users where email='boss@example.cc'")
node "$(dirname "$0")/client_login.node.js" "http://$API" "boss@example.cc" "$PW" "$TESTDIR/rec1" "$WREC" > "$TESTDIR/node.out" 2>&1; NRC=$?
grep -E "PASS|FAIL" "$TESTDIR/node.out" | while read -r l; do echo "$l"; done
[ $NRC -ne 0 ] && { echo "  (node output tail:)"; tail -5 "$TESTDIR/node.out"; }
P=$(grep -c "PASS:" "$TESTDIR/node.out"); F=$(grep -c "FAIL:" "$TESTDIR/node.out")
PASS=$((PASS + P)); FAIL=$((FAIL + F)); [ $NRC -ne 0 ] && [ "$F" = "0" ] && FAIL=$((FAIL + 1))

finish
