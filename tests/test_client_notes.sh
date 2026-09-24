#!/usr/bin/env bash
# Runs the real web/app.js note code (in a VM, with DOM stubs) against a real
# server + real WebCrypto. Needs node.
source "$(dirname "$0")/lib.sh"
command -v node >/dev/null 2>&1 || { echo "  SKIP: node not found"; exit 0; }
start_server 8107 || exit 1
node "$(dirname "$0")/client_notes.node.js" "http://$API" "$TESTDIR/storage"
rc=$?
[ -n "$SRV_PID" ] && kill "$SRV_PID" 2>/dev/null
[ -n "$TESTDIR" ] && rm -rf "$TESTDIR"
exit $rc
