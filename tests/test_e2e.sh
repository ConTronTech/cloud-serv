#!/usr/bin/env bash
# End-to-end zero-knowledge test: drives the real HTTP API exactly like the
# browser client (E2E register -> encrypted upload -> download+decrypt) and
# asserts plaintext never touches disk. Needs node (WebCrypto). Prints its own
# PASS lines + RESULTS and exits non-zero on any failure.
source "$(dirname "$0")/lib.sh"

if ! command -v node >/dev/null 2>&1; then
  echo "  SKIP: node not found"; exit 0
fi

start_server 8099 || exit 1
node "$(dirname "$0")/e2e.node.js" "http://$API" "$TESTDIR/storage"
rc=$?
[ -n "$SRV_PID" ] && kill "$SRV_PID" 2>/dev/null
[ -n "$TESTDIR" ] && rm -rf "$TESTDIR"
exit $rc
