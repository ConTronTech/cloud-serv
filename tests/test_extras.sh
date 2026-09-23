#!/usr/bin/env bash
source "$(dirname "$0")/lib.sh"
start_server 8096 || exit 1
T=$(tok_of "$(curl -s "http://$API/api/auth/register" -d '{"email":"x@e.cc","password":"supersecret","inviteCode":"test-invite"}')")

# varied files
A -X POST "http://$API/api/files" -H "X-Filename: caf.jpg" -H "content-type: image/jpeg" --data-binary "img" >/dev/null
sleep 1
A -X POST "http://$API/api/files" -H "X-Filename: clip.mp4" -H "content-type: video/mp4" --data-binary "vid" >/dev/null
A -X POST "http://$API/api/files" -H "X-Filename: report.pdf" -H "content-type: application/pdf" --data-binary "doc" >/dev/null

echo "== categories =="
want "category=image" 'caf.jpg' "$(A "http://$API/api/search?category=image")"
want "category=image excludes pdf" "$(A "http://$API/api/search?category=image" | grep -o 'report' || echo NONE)" "NONE"
want "category=video" 'clip.mp4' "$(A "http://$API/api/search?category=video")"
want "category=document -> pdf" 'report.pdf' "$(A "http://$API/api/search?category=document")"

echo "== search =="
want "search 'report'" 'report.pdf' "$(A "http://$API/api/search?q=report")"
want "search 'zzz' empty" '"files":[]' "$(A "http://$API/api/search?q=zzz")"
A -X POST "http://$API/api/folders" -d '{"name":"Holiday"}' >/dev/null
want "search matches folders" 'Holiday' "$(A "http://$API/api/search?q=holi")"

echo "== starred + recent =="
FID=$(A "http://$API/api/fs" | tr '}' '\n' | grep 'report.pdf' | grep -o '"id":[0-9]*' | head -1 | cut -d: -f2)
want "star a file" '"starred":true' "$(A -X PATCH "http://$API/api/files/$FID" -d '{"starred":true}')"
want "/api/starred has it" 'report.pdf' "$(A "http://$API/api/starred")"
A -X PATCH "http://$API/api/files/$FID" -d '{"starred":false}' >/dev/null
want "unstar removes it" "$(A "http://$API/api/starred" | grep -o 'report.pdf' || echo NONE)" "NONE"
REC=$(A "http://$API/api/recent")
BPOS=$(printf '%s' "$REC" | grep -bo 'report.pdf' | head -1 | cut -d: -f1)
APOS=$(printf '%s' "$REC" | grep -bo 'caf.jpg' | head -1 | cut -d: -f1)
[ -n "$BPOS" ] && [ -n "$APOS" ] && [ "$BPOS" -lt "$APOS" ] && ok "recent newest-first" || bad "recent order wrong"

finish
