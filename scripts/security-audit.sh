#!/usr/bin/env bash
# Adversarial security + regression test battery for cloud-serv.
# Builds nothing — expects ./cloud_serv to exist (run `make` first).
# Starts a server on a throwaway DB, runs the attack suite, tears down.
#
#   make && ./scripts/security-audit.sh
#
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 1
PORT="${PORT:-8090}"          # separate port so it won't clash with a running instance
API="localhost:$PORT"
TMPDATA="$(mktemp -d)"
SRVLOG="$(mktemp)"
PASS=0; FAIL=0
ok(){ echo "  PASS: $1"; PASS=$((PASS+1)); }
bad(){ echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
want(){ if printf '%s' "$3" | grep -qF -- "$2"; then ok "$1"; else bad "$1 (got: $(printf '%s' "$3" | head -c 80))"; fi; }

# Isolated config: throwaway data dir + test port, so real data is untouched.
TMPCONF="$TMPDATA/config.env"
cat > "$TMPCONF" <<EOF
PORT=$PORT
DB_PATH=$TMPDATA/cloud.db
STORAGE_DIR=$TMPDATA/storage
WEB_DIR=web
SESSION_SECONDS=3600
RATE_LIMIT_ENABLED=false
LOG_LEVEL=WARN
EOF
./cloud_serv "$TMPCONF" > "$SRVLOG" 2>&1 &
SRV=$!
for i in $(seq 1 20); do curl -s "$API/api/health" | grep -q ok && break; sleep 0.2; done
if ! curl -s "$API/api/health" | grep -q ok; then echo "SERVER FAILED TO START"; cat "$SRVLOG"; exit 1; fi
echo "server up on :$PORT"; echo

T1=$(curl -s $API/api/auth/register -d '{"email":"alice@example.com","password":"supersecret"}' | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
T2=$(curl -s $API/api/auth/register -d '{"email":"bob@example.com","password":"supersecret"}'   | grep -o '"token":"[^"]*"' | cut -d'"' -f4)

echo "== SQL injection =="
printf '{"email":"alice@example.com\\u0027 OR 1=1--","password":"x"}' > "$TMPDATA/sqli.json"
want "SQLi OR 1=1 in email -> no bypass" "invalid credentials" "$(curl -s $API/api/auth/login -H 'content-type: application/json' --data-binary @"$TMPDATA/sqli.json")"
curl -s -X POST $API/api/files -H "authorization: Bearer $T1" -H "X-Filename: x.txt" --data-binary "x'); DROP TABLE files;--" >/dev/null
want "files table intact after injection attempt" '"files"' "$(curl -s $API/api/files -H "authorization: Bearer $T1")"

echo "== Path traversal =="
want "traversal in X-Filename rejected" "invalid filename" "$(curl -s -X POST $API/api/files -H "authorization: Bearer $T1" -H 'X-Filename: ../../../../etc/passwd' --data-binary d)"
if curl -s "$API/%2e%2e%2fconfig.env" | grep -q SESSION_SECONDS; then bad "static traversal leaks config.env"; else ok "static traversal blocked (no config leak)"; fi

echo "== IDOR / cross-user =="
UP=$(curl -s -X POST $API/api/files -H "authorization: Bearer $T1" -H "X-Filename: secret.txt" --data-binary 'alice secret')
FID=$(printf '%s' "$UP" | grep -o '"id":[0-9]*' | head -1 | cut -d: -f2)
want "bob cannot download alice's file" "not found" "$(curl -s $API/api/files/$FID -H "authorization: Bearer $T2")"
want "bob cannot delete alice's file"   "not found" "$(curl -s -X DELETE $API/api/files/$FID -H "authorization: Bearer $T2")"

echo "== Auth bypass =="
want "no creds"        "unauthorized" "$(curl -s $API/api/files)"
want "empty bearer"    "unauthorized" "$(curl -s $API/api/files -H 'authorization: Bearer ')"
want "garbage token"   "unauthorized" "$(curl -s $API/api/files -H 'authorization: Bearer deadbeef')"
want "bogus api key"   "unauthorized" "$(curl -s $API/api/files -H 'X-API-Key: csk_nope')"
want "bad key no fallthrough" "unauthorized" "$(curl -s $API/api/files -H 'X-API-Key: bad' -H "authorization: Bearer $T1")"

echo "== Input validation =="
want "malformed JSON"      "invalid json"   "$(curl -s $API/api/auth/login --data-binary '{bad')"
want "short password"      "at least 8"     "$(curl -s $API/api/auth/register -d '{"email":"a@b.cc","password":"short12"}')"
want "bad email"           "invalid email"  "$(curl -s $API/api/auth/register -d '{"email":"nope","password":"supersecret"}')"
want "duplicate email 409" "already registered" "$(curl -s $API/api/auth/register -d '{"email":"alice@example.com","password":"supersecret"}')"

echo "== Logout revocation =="
TX=$(curl -s $API/api/auth/login -d '{"email":"bob@example.com","password":"supersecret"}' | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
curl -s -X POST $API/api/auth/logout -H "authorization: Bearer $TX" >/dev/null
want "revoked session -> unauthorized" "unauthorized" "$(curl -s $API/api/auth/me -H "authorization: Bearer $TX")"

echo
echo "======================================"
echo "RESULTS: $PASS passed, $FAIL failed"
echo "======================================"

kill "$SRV" 2>/dev/null
rm -rf "$TMPDATA" "$SRVLOG"
exit 0
