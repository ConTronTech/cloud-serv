#!/usr/bin/env bash
# Static-file route: traversal / exposure regression tests.
# lib.sh defaults WEB_DIR to an absolute path, which Crow's sanitize_filename mangles (see the
# absolute-WEB_DIR check at the bottom); the main checks use the relative form the server ships with.
EXTRA_CONFIG="WEB_DIR=web"
source "$(dirname "$0")/lib.sh"
start_server 8103 || exit 1

echo "== traversal never leaks config.env or files outside web/ =="
CANARY_A="SESSION_SECONDS"; CANARY_B="REGISTRATION_INVITE_CODE"
for p in "/../config.env" "/%2e%2e/config.env" "/%2e%2e%2fconfig.env" "/..%5cconfig.env" \
         "/a/../../config.env" "/config.env" "/..%2f..%2fetc/passwd" "/%2e%2e%2f%2e%2e%2fetc%2fpasswd"; do
  OUT=$(curl -s --path-as-is -o "$TESTDIR/body" -w '%{http_code}' "http://$API$p")
  BODY=$(cat "$TESTDIR/body")
  if printf '%s' "$BODY" | grep -qF -e "$CANARY_A" -e "$CANARY_B" -e "root:x:0:0"; then
    bad "GET $p leaked file contents (status $OUT)"
  else
    ok "GET $p leaks nothing (status $OUT)"
  fi
  if [ "$OUT" = 200 ] && ! printf '%s' "$BODY" | grep -qi '<!doctype\|<html'; then
    bad "GET $p returned 200 with non-web content"
  else
    ok "GET $p is not a 200 with non-web content"
  fi
done

echo "== dotfiles / backups =="
for p in /.env /app.js.bak /.git /.htaccess; do
  C=$(curl -s --path-as-is -o /dev/null -w '%{http_code}' "http://$API$p")
  [ "$C" = 404 ] && ok "GET $p -> 404" || bad "GET $p -> $C (expected 404)"
done

echo "== real assets still served unauthenticated =="
for p in / /app.js /style.css; do
  C=$(curl -s -o /dev/null -w '%{http_code}' "http://$API$p")
  [ "$C" = 200 ] && ok "GET $p -> 200" || bad "GET $p -> $C"
done

echo "== absolute WEB_DIR =="
kill "$SRV_PID" 2>/dev/null; wait "$SRV_PID" 2>/dev/null
sed -i "s#^WEB_DIR=.*#WEB_DIR=$ROOT/web#" "$TESTDIR/config.env"
launch_server || exit 1
C=$(curl -s -o /dev/null -w '%{http_code}' "http://$API/")
[ "$C" = 200 ] && ok "absolute WEB_DIR serves / (200)" || bad "absolute WEB_DIR: GET / -> $C (static serving broken)"

finish
