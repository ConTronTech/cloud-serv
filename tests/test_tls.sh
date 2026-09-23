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

mkdir -p "$TESTDIR/fakebin"
cat > "$TESTDIR/fakebin/tailscale" <<'EOF'
#!/bin/sh
[ "$1" = ip ] && { echo 100.64.1.2; exit 0; }
exit 1
EOF
chmod +x "$TESTDIR/fakebin/tailscale"
stop() { kill "$SRV_PID" 2>/dev/null; wait "$SRV_PID" 2>/dev/null; }

echo "== CA-signed cert preserved when Tailscale IP detected but not in SAN =="
stop
CA="$TESTDIR/ca"; mkdir -p "$CA"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$CA/ca.key" -out "$CA/ca.crt" -days 2 -subj "/CN=test-ca" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout "$KEY" -out "$CA/leaf.csr" -subj "/CN=localhost" 2>/dev/null
printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\n' > "$CA/ext.cnf"
openssl x509 -req -in "$CA/leaf.csr" -CA "$CA/ca.crt" -CAkey "$CA/ca.key" -CAcreateserial -days 2 -extfile "$CA/ext.cnf" -out "$CRT" 2>/dev/null
chmod 600 "$KEY"
FP0=$(fp); EXTRA_PATH="$TESTDIR/fakebin" launch_server || { bad "start with CA cert failed"; finish; exit 1; }
[ "$FP0" = "$(fp)" ] && ok "CA-signed cert preserved (fake tailscale)" || bad "CA-signed cert was overwritten"

echo "== self-signed cert missing Tailscale IP is regenerated =="
stop
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$KEY" -out "$CRT" -days 2 -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null
chmod 600 "$KEY"
FP1=$(fp); EXTRA_PATH="$TESTDIR/fakebin" launch_server || { bad "start with self-signed cert failed"; finish; exit 1; }
[ "$FP1" != "$(fp)" ] && ok "self-signed cert regenerated" || bad "self-signed cert not regenerated"
want "new SAN contains 100.64.1.2" "100.64.1.2" "$(openssl x509 -in "$CRT" -noout -ext subjectAltName 2>&1)"

echo "== self-signed cert covering Tailscale IP is stable =="
FP2=$(fp); stop; EXTRA_PATH="$TESTDIR/fakebin" launch_server || { bad "restart failed"; finish; exit 1; }
[ "$FP2" = "$(fp)" ] && ok "cert not regenerated on next boot" || bad "cert regenerated every boot"

finish
