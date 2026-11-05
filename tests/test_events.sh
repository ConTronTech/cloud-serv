#!/usr/bin/env bash
# Live change events over WebSocket (/api/events).
source "$(dirname "$0")/lib.sh"
EXTRA_CONFIG=$'REGISTRATION_REQUESTS=true'
start_server 8132 || exit 1
B="http://$API"
TA=$(tok_of "$(curl -s "$B/api/auth/register" -d '{"email":"evadmin@e.cc","password":"supersecret","inviteCode":"test-invite"}')")
TU=$(tok_of "$(curl -s "$B/api/auth/register" -d '{"email":"evuser@e.cc","password":"supersecret","inviteCode":"test-invite"}')")
KEY=$(curl -s -H "authorization: Bearer $TA" -X POST "$B/api/auth/api-keys" -d '{"name":"k"}' | grep -o '"key":"[^"]*"' | cut -d'"' -f4)
if command -v node >/dev/null; then
  node "$(dirname "$0")/events.node.js" "$B" "$TA" "$TU" "$KEY"; RC=$?
  [ $RC -eq 0 ] && ok "websocket event rules" || bad "websocket event rules"
else
  echo "  (node not found, skipping websocket checks)"
fi
finish
