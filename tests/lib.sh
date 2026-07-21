#!/usr/bin/env bash
# Shared test harness. Source from a test_*.sh:
#   source "$(dirname "$0")/lib.sh"; start_server 8091 || exit 1; ... ; finish
#
# Starts ./cloud_serv on a throwaway DB + isolated port (rate limiting off),
# provides assertion helpers, and cleans up on finish.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PASS=0; FAIL=0
SRV_PID=""; TESTDIR=""

# want <desc> <expected-substring> <actual>
want() {
  if printf '%s' "$3" | grep -qF -- "$2"; then
    echo "  PASS: $1"; PASS=$((PASS + 1))
  else
    echo "  FAIL: $1 (got: $(printf '%s' "$3" | head -c 200))"; FAIL=$((FAIL + 1))
  fi
}
ok()  { echo "  PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }
# id_of <json> — first "id":N
id_of() { printf '%s' "$1" | grep -o '"id":[0-9]*' | head -1 | cut -d: -f2; }
# tok_of <json> — session token
tok_of() { printf '%s' "$1" | grep -o '"token":"[^"]*"' | cut -d'"' -f4; }

start_server() {
  local port="${1:-8090}"
  TESTDIR="$(mktemp -d)"
  API="localhost:$port"
  cat > "$TESTDIR/config.env" <<EOF
PORT=$port
DB_PATH=$TESTDIR/cloud.db
STORAGE_DIR=$TESTDIR/storage
WEB_DIR=$ROOT/web
SESSION_SECONDS=3600
RATE_LIMIT_ENABLED=false
LOG_LEVEL=WARN
EOF
  ( cd "$ROOT" && exec ./cloud_serv "$TESTDIR/config.env" ) > "$TESTDIR/server.log" 2>&1 &
  SRV_PID=$!
  local i
  for i in $(seq 1 50); do
    curl -s "http://$API/api/health" 2>/dev/null | grep -q ok && return 0
    kill -0 "$SRV_PID" 2>/dev/null || { echo "SERVER EXITED EARLY"; cat "$TESTDIR/server.log"; return 1; }
    sleep 0.2
  done
  echo "SERVER FAILED TO START"; cat "$TESTDIR/server.log"; return 1
}

# Authenticated curl for the current token: A <curl-args...>
A() { curl -s -H "authorization: Bearer $T" "$@"; }

finish() {
  echo
  echo "RESULTS: $PASS passed, $FAIL failed"
  [ -n "$SRV_PID" ] && kill "$SRV_PID" 2>/dev/null
  [ -n "$TESTDIR" ] && rm -rf "$TESTDIR"
  [ "$FAIL" -eq 0 ]
}
