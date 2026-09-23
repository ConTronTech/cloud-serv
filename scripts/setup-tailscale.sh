#!/usr/bin/env bash
# setup-tailscale.sh — installs Tailscale (if missing), brings it up, and prints the
# tailnet IP/hostname. Run as root (or a sudo-capable user). Idempotent.
#
# `tailscale up` is interactive: it prints a login URL to open in a browser.
# cloud-serv does not need config changes afterwards — on next start it detects the
# Tailscale IP and regenerates its TLS cert SAN if needed.
set -euo pipefail

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    command -v sudo >/dev/null || { echo "must run as root or have sudo" >&2; exit 1; }
    SUDO="sudo"
fi

if ! command -v tailscale >/dev/null 2>&1; then
    echo "==> installing tailscale"
    if command -v apt-get >/dev/null 2>&1; then
        $SUDO apt-get update
        $SUDO apt-get install -y curl
        # tailscale is not in default apt repos; use the official installer (adds the apt repo).
        curl -fsSL https://tailscale.com/install.sh | $SUDO sh
    else
        echo "apt-get not found; install tailscale manually: https://tailscale.com/download" >&2
        exit 1
    fi
else
    echo "==> tailscale already installed"
fi

$SUDO systemctl enable --now tailscaled 2>/dev/null || true

if TS_IP="$($SUDO tailscale ip -4 2>/dev/null | head -n1)" && [ -n "$TS_IP" ]; then
    echo "==> already connected"
else
    echo "==> running 'tailscale up' — open the login URL it prints"
    $SUDO tailscale up
    TS_IP="$($SUDO tailscale ip -4 | head -n1)"
fi

HOST="$($SUDO tailscale status --self --peers=false 2>/dev/null | awk 'NR==1{print $2}')"
echo
echo "Tailscale connected."
echo "  tailnet IP : $TS_IP"
echo "  hostname   : ${HOST:-unknown}"
echo "Restart cloud-serv; it will add $TS_IP to its TLS certificate automatically."
