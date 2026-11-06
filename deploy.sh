#!/usr/bin/env bash
# deploy.sh: install (or update) cloud-serv as a systemd service on a Debian/Ubuntu box
# or Proxmox CT. Run as root from the extracted source folder:
#
#   unzip cloud-serv-deploy.zip -d /opt && cd /opt/cloud-serv && ./deploy.sh
#
# First run: asks a few questions (port, sign-up mode, quota, encryption, optional
# authentik), builds, creates the service user + folders, writes the config, installs
# and starts the service, and offers to create your admin account.
# Later runs: rebuild + restart, config and data left alone. That is how you update.
#
# Options:
#   --yes            no questions; use defaults (or the CS_* variables below)
#   --no-build       skip the compile step (binary already built)
#   --uninstall      stop + remove the service and tools (keeps data + config)
#   -h | --help
#
# Unattended defaults can be preset: CS_PORT CS_SIGNUP (closed|requests|code)
# CS_QUOTA_GB CS_ENCRYPT (true|false) CS_ADMIN_EMAIL CS_DATA_DIR
#
# Layout it creates:
#   <this folder>                 code + binary (the service's working directory)
#   /etc/cloud-serv/config.env    config (root:cloudserv 0640; holds secrets)
#   /etc/cloud-serv/install.env   where things are, for cloudctl
#   /var/lib/cloud-serv/          database, files, avatars, backups, TLS (cloudserv 0700)
#   /usr/local/bin/cloudctl       server management tool
#   /usr/local/bin/cloud          command-line client
set -euo pipefail

SERVICE=cloud-serv
SVC_USER=cloudserv
ETC=/etc/cloud-serv
UNIT=/etc/systemd/system/$SERVICE.service
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA="${CS_DATA_DIR:-/var/lib/cloud-serv}"
YES=0; BUILD=1

say()  { printf '\033[1;35m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mxx\033[0m %s\n' "$*" >&2; exit 1; }
ask()  { # ask <var> <question> <default>
    local __v="$1" q="$2" def="$3" a
    if [ "$YES" = 1 ]; then printf -v "$__v" '%s' "$def"; return; fi
    read -r -p "$q [$def]: " a </dev/tty || true
    printf -v "$__v" '%s' "${a:-$def}"
}
yesno() { # yesno <question> <default y|n>  -> exit status
    local a; if [ "$YES" = 1 ]; then [ "$2" = y ]; return; fi
    read -r -p "$1 [$( [ "$2" = y ] && echo Y/n || echo y/N )]: " a </dev/tty || true
    a="${a:-$2}"; [[ "$a" =~ ^[Yy] ]]
}

for arg in "$@"; do
    case "$arg" in
        --yes|-y) YES=1 ;;
        --no-build) BUILD=0 ;;
        --uninstall) UNINSTALL=1 ;;
        -h|--help) sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown option: $arg (see --help)" ;;
    esac
done
[ "$(id -u)" -eq 0 ] || die "run as root: it installs packages, a system user and a systemd service"

if [ "${UNINSTALL:-0}" = 1 ]; then
    say "stopping and removing the service"
    systemctl disable --now "$SERVICE" 2>/dev/null || true
    rm -f "$UNIT" /usr/local/bin/cloudctl /usr/local/bin/cloud
    systemctl daemon-reload
    say "done. Kept: $DATA (your files + database) and $ETC (config). Delete them yourself if you mean it."
    exit 0
fi

FRESH=1; [ -f "$ETC/config.env" ] && FRESH=0

# ---- 0. questions first, so the long build can run unattended ---------------------
if [ "$FRESH" = 1 ]; then
    say "first-time setup: a few questions (Enter = default)"
    ask PORT "Port to serve HTTPS on" "${CS_PORT:-8443}"
    [[ "$PORT" =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ] || die "bad port: $PORT"
    echo "How do new people get an account?"
    echo "  closed   = only accounts you create or one-time invites from the Admin page"
    echo "  requests = anyone can ask; you approve or deny on the Admin page"
    echo "  code     = anyone with a shared code you set"
    ask SIGNUP "Sign-up mode (closed/requests/code)" "${CS_SIGNUP:-requests}"
    case "$SIGNUP" in closed|requests|code) ;; *) die "sign-up mode must be closed, requests or code" ;; esac
    CODE=""; [ "$SIGNUP" = code ] && CODE="$(head -c 18 /dev/urandom | base64 | tr -d '/+=' | head -c 24)"
    ask QUOTA "Default storage per new account in GB (0 = unlimited)" "${CS_QUOTA_GB:-0}"
    [[ "$QUOTA" =~ ^[0-9]+$ ]] || die "quota must be a whole number of GB"
    ask ENC "Encrypt new users' files in the browser by default? (true/false)" "${CS_ENCRYPT:-false}"
    case "$ENC" in true|false) ;; *) die "answer true or false" ;; esac
    OIDC_ISS=""; OIDC_ID=""; OIDC_SEC=""
    if yesno "Set up 'Sign in with authentik' (OpenID Connect) now?" n; then
        ask OIDC_ISS "Issuer URL (ends in /application/o/<slug>/)" ""
        ask OIDC_ID "Client ID" ""
        read -r -s -p "Client secret (hidden): " OIDC_SEC </dev/tty; echo
    fi

    if [ "$YES" = 0 ]; then
        MAKE_ADMIN=0
        if yesno "Create your admin account now?" y; then
            ask AEMAIL "Admin email" "${CS_ADMIN_EMAIL:-}"
            [ -n "$AEMAIL" ] || die "an email is required"
            while :; do
                read -r -s -p "Admin password (8+ characters, hidden): " APASS </dev/tty; echo
                read -r -s -p "Same again: " APASS2 </dev/tty; echo
                [ "$APASS" = "$APASS2" ] && [ ${#APASS} -ge 8 ] && break
                warn "they didn't match or were under 8 characters; try again"
            done
            unset APASS2; MAKE_ADMIN=1
        fi
    fi
    say "thanks, that's everything: building and installing now (no more questions)"
fi

# ---- 1. packages + build ---------------------------------------------------------
if [ "$BUILD" = 1 ]; then
    say "installing build packages"
    command -v apt-get >/dev/null || die "apt-get not found: install g++ make libasio-dev libssl-dev libsqlite3-dev libcurl4-openssl-dev yourself, then use --no-build after running make"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq </dev/null
    apt-get install -y -qq --no-install-recommends g++ make libasio-dev libssl-dev libsqlite3-dev \
        libcurl4-openssl-dev ca-certificates python3 curl zip unzip </dev/null >/dev/null
    # A new version always gets a clean build: zip files keep timestamps without a time
    # zone, so make can wrongly think old object files are newer than updated sources.
    if [ "$(cat "$SRC/VERSION" 2>/dev/null)" != "$(cat "$SRC/.built-version" 2>/dev/null)" ]; then
        make -C "$SRC" clean </dev/null >/dev/null 2>&1 || true
    fi
    say "building (this takes a few minutes on a small box)"
    make -C "$SRC" -j"$(nproc)" </dev/null >/dev/null
    cat "$SRC/VERSION" > "$SRC/.built-version" 2>/dev/null || true
fi
[ -x "$SRC/cloud_serv" ] || die "no cloud_serv binary in $SRC (build failed?)"

# ---- 2. user + folders -----------------------------------------------------------
id "$SVC_USER" >/dev/null 2>&1 || { say "creating service user $SVC_USER"; useradd --system --home "$DATA" --shell /usr/sbin/nologin "$SVC_USER"; }
install -d -m 0700 -o "$SVC_USER" -g "$SVC_USER" "$DATA" "$DATA/storage" "$DATA/avatars" "$DATA/backups" "$DATA/tls"
install -d -m 0750 -o root -g "$SVC_USER" "$ETC"

# ---- 3. config (first run only) --------------------------------------------------
if [ "$FRESH" = 1 ]; then
    say "writing $ETC/config.env"
    umask 027
    sed -e "s|^PORT=.*|PORT=$PORT|" \
        -e "s|^BIND_ADDRESS=.*|BIND_ADDRESS=0.0.0.0|" \
        -e "s|^DB_PATH=.*|DB_PATH=$DATA/cloud.db|" \
        -e "s|^STORAGE_DIR=.*|STORAGE_DIR=$DATA/storage|" \
        -e "s|^WEB_DIR=.*|WEB_DIR=$SRC/web|" \
        -e "s|^TLS_CERT_PATH=.*|TLS_CERT_PATH=$DATA/tls/server.crt|" \
        -e "s|^TLS_KEY_PATH=.*|TLS_KEY_PATH=$DATA/tls/server.key|" \
        -e "s|^CORS_ORIGINS=.*|CORS_ORIGINS=|" \
        -e "s|^REGISTRATION_INVITE_CODE=.*|REGISTRATION_INVITE_CODE=$CODE|" \
        -e "s|^REGISTRATION_REQUESTS=.*|REGISTRATION_REQUESTS=$( [ "$SIGNUP" = requests ] && echo true || echo false )|" \
        -e "s|^DEFAULT_STORAGE_QUOTA_GB=.*|DEFAULT_STORAGE_QUOTA_GB=$QUOTA|" \
        -e "s|^FILES_ENCRYPT_DEFAULT=.*|FILES_ENCRYPT_DEFAULT=$ENC|" \
        -e "s|^BACKUP_DIR=.*|BACKUP_DIR=$DATA/backups|" \
        -e "s|^AVATAR_DIR=.*|AVATAR_DIR=$DATA/avatars|" \
        -e "s|^OIDC_ISSUER=.*|OIDC_ISSUER=$OIDC_ISS|" \
        -e "s|^OIDC_CLIENT_ID=.*|OIDC_CLIENT_ID=$OIDC_ID|" \
        "$SRC/config.env.example" > "$ETC/config.env"
    # the secret goes in with printf, never through sed (it could hold | or &)
    if [ -n "$OIDC_SEC" ]; then
        grep -v '^OIDC_CLIENT_SECRET=' "$ETC/config.env" > "$ETC/config.env.tmp"
        printf 'OIDC_CLIENT_SECRET=%s\n' "$OIDC_SEC" >> "$ETC/config.env.tmp"
        mv "$ETC/config.env.tmp" "$ETC/config.env"
    fi
    chown root:"$SVC_USER" "$ETC/config.env"; chmod 0640 "$ETC/config.env"
    [ -n "$CODE" ] && say "shared sign-up code: $CODE  (also in $ETC/config.env)"
else
    say "existing config kept: $ETC/config.env"
    PORT="$(grep -E '^PORT=' "$ETC/config.env" | cut -d= -f2)"
fi

cat > "$ETC/install.env" <<EOF
# written by deploy.sh; read by cloudctl
SERVICE=$SERVICE
SVC_USER=$SVC_USER
INSTALL_DIR=$SRC
DATA_DIR=$DATA
CONFIG=$ETC/config.env
EOF
chmod 0644 "$ETC/install.env"

# ---- 4. systemd service ----------------------------------------------------------
say "installing the systemd service"
CAPS="CapabilityBoundingSet="
[ "${PORT:-8443}" -lt 1024 ] && CAPS=$'AmbientCapabilities=CAP_NET_BIND_SERVICE\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE'
cat > "$UNIT" <<EOF
[Unit]
Description=cloud-serv personal cloud
Documentation=file://$SRC/docs/README.md
After=network-online.target tailscaled.service
Wants=network-online.target

[Service]
Type=simple
User=$SVC_USER
Group=$SVC_USER
WorkingDirectory=$SRC
ExecStart=$SRC/cloud_serv $ETC/config.env
# SIGTERM = graceful: finishes in-flight requests, closes the database cleanly
KillSignal=SIGTERM
TimeoutStopSec=30
Restart=on-failure
RestartSec=3
UMask=0077
$CAPS
# hardening: read-only system, writable data dir only, no privilege escalation
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=$DATA
ProtectHome=read-only
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
RestrictNamespaces=true
RestrictRealtime=true
MemoryDenyWriteExecute=true
ProtectClock=true
ProtectHostname=true
ProtectKernelLogs=true
ProtectProc=invisible
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable "$SERVICE" >/dev/null 2>&1

# ---- 5. tools --------------------------------------------------------------------
ln -sf "$SRC/Companion-apps/cli/cloudctl" /usr/local/bin/cloudctl
ln -sf "$SRC/Companion-apps/cli/cloud" /usr/local/bin/cloud
chmod 0755 "$SRC/Companion-apps/cli/cloudctl" "$SRC/Companion-apps/cli/cloud"

# ---- 6. admin account (first run) ------------------------------------------------
if [ "${MAKE_ADMIN:-0}" = 1 ]; then
    say "creating admin account $AEMAIL"
    REC="$ETC/recovery-$(date +%Y%m%d-%H%M%S).txt"
    printf '%s\n' "$APASS" | runuser -u "$SVC_USER" -- "$SRC/cloud_serv" admin create-admin --email "$AEMAIL" \
        --config "$ETC/config.env" --password-stdin --recovery-key-file "$DATA/recovery.tmp" | sed "s|$DATA/recovery.tmp|$REC|"
    unset APASS
    mv "$DATA/recovery.tmp" "$REC"; chown root:root "$REC"; chmod 0600 "$REC"
    warn "your RECOVERY KEY is in $REC: copy it somewhere safe (password manager), then delete that file"
fi

# ---- 7. start --------------------------------------------------------------------
say "starting $SERVICE"
systemctl restart "$SERVICE"
for _ in $(seq 1 30); do
    curl -sk "https://127.0.0.1:${PORT:-8443}/api/health" 2>/dev/null | grep -q ok && break
    curl -s  "http://127.0.0.1:${PORT:-8443}/api/health" 2>/dev/null | grep -q ok && break
    sleep 0.5
done
if systemctl is-active --quiet "$SERVICE"; then
    say "cloud-serv is running"
    /usr/local/bin/cloudctl url || true
    echo; echo "Manage it with: cloudctl   (status, logs, backup, update ...; 'cloudctl help')"
else
    warn "the service did not start; last log lines:"
    journalctl -u "$SERVICE" -n 30 --no-pager || true
    exit 1
fi
