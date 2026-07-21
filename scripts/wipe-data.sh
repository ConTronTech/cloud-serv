#!/usr/bin/env bash
# Wipe the local DB + stored blobs for a clean test run. The server recreates a
# fresh (empty) DB + storage dir on next start.
#
#   scripts/wipe-data.sh [config-file]   # default: config.env
#
# Refuses to run while a cloud_serv process is alive (wiping the DB out from
# under a running server corrupts it). Pass --force to override.
set -euo pipefail

FORCE=0
CONFIG="config.env"
for arg in "$@"; do
  case "$arg" in
    --force) FORCE=1 ;;
    *) CONFIG="$arg" ;;
  esac
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [ ! -f "$CONFIG" ]; then
  echo "config not found: $CONFIG" >&2
  exit 1
fi

# Pull the paths from the config so we always wipe what the server actually uses.
val() { grep -E "^$1=" "$CONFIG" | head -1 | cut -d= -f2- | tr -d '[:space:]'; }
DB_PATH="$(val DB_PATH)"; DB_PATH="${DB_PATH:-data/cloud.db}"
STORAGE_DIR="$(val STORAGE_DIR)"; STORAGE_DIR="${STORAGE_DIR:-data/storage}"

if [ "$FORCE" -ne 1 ] && pgrep -x cloud_serv >/dev/null 2>&1; then
  echo "cloud_serv is running — stop it first (or pass --force)." >&2
  exit 1
fi

echo "Wiping:"
echo "  DB:      $DB_PATH (+ -wal, -shm)"
echo "  Storage: $STORAGE_DIR"

rm -f -- "$DB_PATH" "$DB_PATH-wal" "$DB_PATH-shm"
rm -rf -- "$STORAGE_DIR"

echo "Done — a fresh DB + storage will be created on next server start."
