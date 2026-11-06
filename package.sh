#!/usr/bin/env bash
# package.sh: build the deploy zip on THIS machine, to copy to the server and run deploy.sh.
#
#   ./package.sh [output.zip]          default: ./cloud-serv-deploy.zip
#   ./package.sh --dirty [out.zip]     also include uncommitted changes (testing only)
#
# Contents: every git-tracked file at HEAD (code, web client, docs, Companion-apps),
# unpacked into a cloud-serv/ folder. Never included: config.env, data/ (database +
# files), TLS keys, recovery keys. Those stay on the box they belong to; move data
# with `cloudctl backup` / `cloudctl restore` instead.
#
# Then on the server:
#   scp cloud-serv-deploy.zip root@<server>:/opt/
#   ssh root@<server> 'cd /opt && unzip -o cloud-serv-deploy.zip && cd cloud-serv && ./deploy.sh'
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIRTY=0
[ "${1:-}" = "--dirty" ] && { DIRTY=1; shift; }
OUT="${1:-$REPO/cloud-serv-deploy.zip}"
case "$OUT" in /*) ;; *) OUT="$PWD/$OUT" ;; esac

command -v zip >/dev/null || { echo "zip is not installed" >&2; exit 1; }
cd "$REPO"
if [ "$DIRTY" = 0 ] && [ -n "$(git status --porcelain)" ]; then
    echo "uncommitted changes: commit them first, or use --dirty to package the working tree" >&2
    git status --short >&2
    exit 1
fi

STAGE="$(mktemp -d)"; trap 'rm -rf "$STAGE"' EXIT
if [ "$DIRTY" = 1 ]; then
    # tracked + new (not ignored) files, as they are on disk now
    git ls-files -co --exclude-standard -z | while IFS= read -r -d '' f; do
        [ -f "$f" ] && install -D -m "$(stat -c %a "$f")" "$f" "$STAGE/cloud-serv/$f"
    done
else
    git archive --format=tar --prefix=cloud-serv/ HEAD | tar -x -C "$STAGE"
fi
# belt and braces: nothing secret may ride along
for bad in config.env data recovery '*.key'; do
    if find "$STAGE/cloud-serv" -name "$bad" -not -path '*/libs/*' | grep -q .; then
        echo "refusing: '$bad' ended up in the package" >&2; exit 1
    fi
done
VER="$(git describe --always --dirty 2>/dev/null || echo unknown)"
echo "$VER" > "$STAGE/cloud-serv/VERSION"
rm -f "$OUT"
(cd "$STAGE" && zip -qr -X "$OUT" cloud-serv)
echo "built $OUT ($(du -h "$OUT" | cut -f1), version $VER)"
echo "next:  scp \"$OUT\" root@<server>:/opt/  then on the server:"
echo "       cd /opt && unzip -o $(basename "$OUT") && cd cloud-serv && ./deploy.sh"
