#!/usr/bin/env bash
source "$(dirname "$0")/lib.sh"
TLS=1 start_server 8100 || exit 1
CRT="$TESTDIR/tls/server.crt"; KEY="$TESTDIR/tls/server.key"
fp() { openssl x509 -in "$CRT" -noout -fingerprint -sha256; }

echo "== https / plain http =="
want "https health ok (curl -k)" ok "$(curl -sk "https://$API/api/health")"
PLAIN=$(curl -s --max-time 3 "http://$API/api/health" 2>&1)
if printf '%s' "$PLAIN" | grep -q '"ok"\|status'; then bad "plain http returned health response"; else ok "plain http gets no valid health response"; fi

echo "== key/cert permissions =="
want "key mode 600" 600 "$(stat -c %a "$KEY")"
want "tls dir mode 700" 700 "$(stat -c %a "$TESTDIR/tls")"

echo "== cert SAN =="
SAN=$(openssl x509 -in "$CRT" -noout -ext subjectAltName 2>&1)
want "SAN has 127.0.0.1" "127.0.0.1" "$SAN"
want "SAN has localhost" "localhost" "$SAN"

restart() {
  kill "$SRV_PID" 2>/dev/null; wait "$SRV_PID" 2>/dev/null
  launch_server
}

echo "== restart reuses cert =="
F1=$(fp); restart || { bad "restart failed"; finish; exit 1; }
[ "$F1" = "$(fp)" ] && ok "cert unchanged after restart" || bad "cert regenerated on restart"

echo "== deleted cert regenerates =="
rm -f "$CRT"; restart || { bad "restart failed"; finish; exit 1; }
[ -f "$CRT" ] && [ "$F1" != "$(fp)" ] && ok "cert regenerated after delete" || bad "cert not regenerated"
want "https still healthy" ok "$(curl -sk "https://$API/api/health")"

finish
