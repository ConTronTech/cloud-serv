#!/usr/bin/env bash
# Trusted devices + first-time key setup (server side: storage, rules, isolation).
source "$(dirname "$0")/lib.sh"
start_server 8129 || exit 1
B="http://$API"
T=$(tok_of "$(curl -s "$B/api/auth/register" -d '{"email":"d@e.cc","password":"supersecret","inviteCode":"test-invite"}')")
T2=$(tok_of "$(curl -s "$B/api/auth/register" -d '{"email":"other@e.cc","password":"supersecret","inviteCode":"test-invite"}')")
PUB="MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE$(head -c 48 /dev/urandom | base64 | tr -d '\n=' | head -c 86)"
SEALED="v1.QUJD.REVG.R0hJ"

echo "== list / create =="
want "empty list" '"devices":[]' "$(A "$B/api/devices")"
R=$(A -X POST "$B/api/devices" -d "{\"name\":\"Chrome on Linux\",\"publicKey\":\"$PUB\"}")
want "pending device created" '"status":"pending"' "$R"; PID1=$(id_of "$R")
R=$(A -X POST "$B/api/devices" -d "{\"name\":\"Laptop\",\"publicKey\":\"$PUB\",\"wrappedDek\":\"$SEALED\"}")
want "self-enrolled device approved at once" '"status":"approved"' "$R"; AID=$(id_of "$R")
want "name control chars stripped" '"name":"Bad Name"' "$(A -X POST "$B/api/devices" -d "{\"name\":\"Bad\\u0007 Name\",\"publicKey\":\"$PUB\",\"wrappedDek\":\"$SEALED\"}")"
want "bad public key rejected" 'invalid public key' "$(A -X POST "$B/api/devices" -d '{"name":"x","publicKey":"<script>"}')"
want "bad sealed key rejected" 'invalid key material' "$(A -X POST "$B/api/devices" -d "{\"name\":\"x\",\"publicKey\":\"$PUB\",\"wrappedDek\":\"a b\"}")"
for i in 2 3 4 5; do A -X POST "$B/api/devices" -d "{\"name\":\"p$i\",\"publicKey\":\"$PUB\"}" >/dev/null; done
want "max 5 pending at once" 'waiting for approval' "$(A -X POST "$B/api/devices" -d "{\"name\":\"p6\",\"publicKey\":\"$PUB\"}")"

echo "== key fetch / approve =="
want "pending key: no sealed key yet" '"status":"pending","wrappedDek":""' "$(A "$B/api/devices/$PID1/key")"
want "approve pending" '"ok":true' "$(A -X POST "$B/api/devices/$PID1/approve" -d "{\"wrappedDek\":\"$SEALED\"}")"
want "now approved with sealed key" "\"wrappedDek\":\"$SEALED\"" "$(A "$B/api/devices/$PID1/key")"
want "can't re-approve (no overwrite)" 'no pending device' "$(A -X POST "$B/api/devices/$PID1/approve" -d "{\"wrappedDek\":\"$SEALED\"}")"
want "approve needs sealed key" 'invalid key material' "$(A -X POST "$B/api/devices/$PID1/approve" -d '{}')"
want "last used recorded" '"lastUsedAt":"2' "$(A "$B/api/devices")"

echo "== isolation between accounts =="
want "other user can't see my devices" '"devices":[]' "$(curl -s -H "authorization: Bearer $T2" "$B/api/devices")"
want "other user can't read my sealed key" 'not found' "$(curl -s -H "authorization: Bearer $T2" "$B/api/devices/$PID1/key")"
want "other user can't revoke mine" 'not found' "$(curl -s -H "authorization: Bearer $T2" -X DELETE "$B/api/devices/$AID")"

echo "== API keys can't touch device trust =="
KEY=$(A -X POST "$B/api/auth/api-keys" -d '{"name":"k"}' | grep -o '"key":"[^"]*"' | cut -d'"' -f4)
want "api key: list refused" 'unauthorized' "$(curl -s -H "X-API-Key: $KEY" "$B/api/devices")"
want "api key: enroll refused" 'unauthorized' "$(curl -s -H "X-API-Key: $KEY" -X POST "$B/api/devices" -d "{\"name\":\"x\",\"publicKey\":\"$PUB\",\"wrappedDek\":\"$SEALED\"}")"
want "api key: read sealed key refused" 'unauthorized' "$(curl -s -H "X-API-Key: $KEY" "$B/api/devices/$PID1/key")"
want "no auth refused" 'unauthorized' "$(curl -s "$B/api/devices")"

echo "== revoke =="
want "revoke" '"ok":true' "$(A -X DELETE "$B/api/devices/$PID1")"
want "revoked device's key gone" 'not found' "$(A "$B/api/devices/$PID1/key")"

echo "== first-time key setup =="
want "keyless account: init ok" '"ok":true' "$(A -X POST "$B/api/keys/init" -d '{"wrappedDekRecovery":"aaaa.bbbb"}')"
want "me now has recovery wrap" '"wrappedDekRecovery":"aaaa.bbbb"' "$(A "$B/api/auth/me")"
want "init can't overwrite existing keys" 'already set up' "$(A -X POST "$B/api/keys/init" -d '{"wrappedDekRecovery":"cccc.dddd"}')"
want "init validates key material" 'invalid key material' "$(curl -s -H "authorization: Bearer $T2" -X POST "$B/api/keys/init" -d '{"wrappedDekRecovery":"nodot"}')"
finish
