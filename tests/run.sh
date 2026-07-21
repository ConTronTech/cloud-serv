#!/usr/bin/env bash
# Build the server, then run the whole test suite. Exit non-zero on any failure.
#   bash tests/run.sh
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
FAILED=""

echo "=== build ==="
make -s || { echo "BUILD FAILED"; exit 1; }

if command -v node >/dev/null 2>&1; then
  echo; echo "=== crypto.test.js (node) ==="
  node tests/crypto.test.js || FAILED=1
else
  echo "!! node not found — skipping crypto unit test"
fi

for t in tests/test_*.sh; do
  [ -e "$t" ] || continue
  echo; echo "=== $t ==="
  bash "$t" || FAILED=1
done

echo
if [ -z "$FAILED" ]; then echo "✅ ALL TESTS PASSED"; else echo "❌ SOME TESTS FAILED"; exit 1; fi
