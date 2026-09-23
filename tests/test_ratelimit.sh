#!/usr/bin/env bash
# Rate limiter + X-Forwarded-For (H1) + security headers on early-ended responses.
BURST=5
EXTRA_CONFIG=$'RATE_LIMIT_ENABLED=true\nBURST_SIZE=5\nREAD_RPM=60\nWRITE_RPM=60\nBAN_THRESHOLD=100000\nBAN_DURATION=1\nTRUSTED_PROXIES=\nMAX_BODY_SIZE=2000'
source "$(dirname "$0")/lib.sh"
start_server 8104 || exit 1
LOGIN="http://$API/api/auth/login"

# hit [xff] -> status of a cheap (400, malformed JSON) write request; consumes a bucket token.
hit() {
  if [ $# -gt 0 ]; then curl -s -o /dev/null -w '%{http_code}' -H "X-Forwarded-For: $1" "$LOGIN" -d '{bad'
  else curl -s -o /dev/null -w '%{http_code}' "$LOGIN" -d '{bad'; fi
}
# n429 <count> [xff] -> how many of <count> back-to-back requests were 429
n429() { local n=$1 i c=0; shift; for i in $(seq 1 "$n"); do [ "$(hit "$@")" = 429 ] && c=$((c+1)); done; echo "$c"; }

echo "== limiter trips on a plain burst =="
C=$(n429 $((BURST + 10)))
[ "$C" -ge 1 ] && ok "burst of $((BURST+10)) from one peer gets 429s ($C)" || bad "no 429 in burst"

echo "== (a) TRUSTED_PROXIES empty: spoofed XFF does not reset the bucket =="
sleep 6   # let the direct-peer bucket refill so this phase starts clean
C=0
for i in $(seq 1 $((BURST + 10))); do
  [ "$(hit "$((RANDOM%223+1)).$((RANDOM%256)).$((RANDOM%256)).$((RANDOM%256))")" = 429 ] && C=$((C+1))
done
[ "$C" -ge 5 ] && ok "random XFF per request still rate-limited ($C x 429)" || bad "XFF spoofing evaded limiter ($C x 429)"

echo "== switch to TRUSTED_PROXIES=127.0.0.1 =="
kill "$SRV_PID" 2>/dev/null; wait "$SRV_PID" 2>/dev/null
sed -i 's/^TRUSTED_PROXIES=.*/TRUSTED_PROXIES=127.0.0.1/' "$TESTDIR/config.env"
launch_server || exit 1

echo "== (b) rightmost untrusted XFF entry is the identity =="
C=0; for i in $(seq 1 $((BURST + 8))); do [ "$(hit "9.9.9.$i, 5.5.5.5")" = 429 ] && C=$((C+1)); done
[ "$C" -ge 5 ] && ok "varying only the LEFT entry shares one bucket ($C x 429)" || bad "left-entry variation escaped the bucket ($C x 429)"
C=$(n429 3 "9.9.9.9, 5.5.5.5")
[ "$C" -ge 1 ] && ok "5.5.5.5 bucket is exhausted" || bad "5.5.5.5 bucket not exhausted"
S=$(hit "9.9.9.9, 5.5.5.6")
[ "$S" != 429 ] && ok "different RIGHTMOST entry gets its own fresh bucket (status $S)" || bad "fresh rightmost entry was throttled"
ALLFRESH=1
for i in 11 12 13 14 15 16; do [ "$(hit "1.1.1.1, 6.6.6.$i")" = 429 ] && ALLFRESH=0; done
[ "$ALLFRESH" = 1 ] && ok "each distinct rightmost entry has its own bucket" || bad "distinct rightmost entries shared a bucket"
C=$(n429 3 "5.5.5.5, 127.0.0.1")
[ "$C" -ge 1 ] && ok "trailing trusted proxy skipped: chain resolves to 5.5.5.5 (exhausted)" || bad "chain '5.5.5.5, 127.0.0.1' did not resolve to 5.5.5.5"
S=$(hit "5.5.5.9, 127.0.0.1")
[ "$S" != 429 ] && ok "chain '5.5.5.9, 127.0.0.1' resolves to fresh 5.5.5.9 (status $S)" || bad "5.5.5.9 throttled"

# exhaust the direct peer's own bucket (no XFF), then garbage must resolve to it
n429 $((BURST + 5)) >/dev/null
C=$(n429 3 "not-an-ip")
[ "$C" -ge 1 ] && ok "garbage XFF fails closed to the direct peer bucket" || bad "garbage XFF did not resolve to direct peer"
C=$(n429 3 "1.2.3.4, not-an-ip")
[ "$C" -ge 1 ] && ok "garbage RIGHTMOST token fails closed to direct peer (spoofable left entry ignored)" || bad "garbage rightmost token trusted"
[ "$(curl -s -o /dev/null -w '%{http_code}' "http://$API/api/health")" != "000" ] && ok "server survived garbage XFF" || bad "server down after garbage XFF"

echo "== (c) IPv6 loopback normalisation =="
# SKIPPED (not faked): Crow binds 0.0.0.0 only, so the harness cannot curl over ::1.
# normalizeIp(::1 -> 127.0.0.1) is only reachable through a v6 listener.
echo "  SKIP: server has no ::1 listener"

echo "== (d) security headers on early-ended responses =="
hdr_check() { # name, headers
  local n="$1" h="$2"
  printf '%s' "$h" | grep -qi '^x-content-type-options: nosniff' && ok "$n: X-Content-Type-Options" || bad "$n: missing X-Content-Type-Options"
  printf '%s' "$h" | grep -qi '^x-frame-options:' && ok "$n: X-Frame-Options" || bad "$n: missing X-Frame-Options"
  printf '%s' "$h" | grep -qi '^content-security-policy:' && ok "$n: Content-Security-Policy" || bad "$n: missing Content-Security-Policy"
}
H=$(curl -s -D - -o /dev/null -H "X-Forwarded-For: 5.5.5.5" "$LOGIN" -d '{bad')
printf '%s' "$H" | head -1 | grep -q 429 || H=$(curl -s -D - -o /dev/null -H "X-Forwarded-For: 5.5.5.5" "$LOGIN" -d '{bad')
printf '%s' "$H" | head -1 | grep -q 429 && ok "429 response obtained" || bad "could not obtain a 429 response"
hdr_check "429" "$H"
H=$(curl -s -D - -o /dev/null -H "X-Forwarded-For: 7.7.7.1" -H "Origin: http://evil.example" "$LOGIN" -d '{}')
printf '%s' "$H" | head -1 | grep -q 403 && ok "403 CSRF response obtained" || bad "no 403 CSRF: $(printf '%s' "$H" | head -1)"
hdr_check "403 CSRF" "$H"
BIG=$(head -c 5000 /dev/zero | tr '\0' 'a')
H=$(curl -s -D - -o /dev/null -H "X-Forwarded-For: 7.7.7.2" "$LOGIN" -d "$BIG")
printf '%s' "$H" | head -1 | grep -q 413 && ok "413 response obtained" || bad "no 413: $(printf '%s' "$H" | head -1)"
hdr_check "413" "$H"

finish
