#!/usr/bin/env bash
# Update awareness: /api/health reports version + updating; open tabs hear "updating".
source "$(dirname "$0")/lib.sh"
STAGED="$ROOT/.web-next"
[ -e "$STAGED" ] && { echo "  $STAGED exists already; not touching it"; exit 1; }
start_server 8134 || exit 1
B="http://$API"
H=$(curl -s "$B/api/health")
want "health has version" '"version":"' "$H"
want "not updating" '"updating":false' "$H"
T=$(tok_of "$(curl -s "$B/api/auth/register" -d '{"email":"up@e.cc","password":"supersecret","inviteCode":"test-invite"}')")
if command -v node >/dev/null; then
  node "$(dirname "$0")/update_notice.node.js" "$B" "$T" "$STAGED" && ok "tab hears 'updating' once" || bad "no 'updating' event"
else
  mkdir "$STAGED"; sleep 3
fi
want "updating while staged" '"updating":true' "$(curl -s "$B/api/health")"
rmdir "$STAGED"
want "back to not updating" '"updating":false' "$(curl -s "$B/api/health")"
finish
