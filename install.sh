#!/usr/bin/env bash
#
# YingNode-Backend one-line installer.
#
# Usage (on a fresh VPS):
#
#     bash <(curl -sL https://raw.githubusercontent.com/DengShiyingA/YingNode-Backend/main/install.sh)
#
# Or to uninstall:
#
#     bash <(curl -sL https://raw.githubusercontent.com/DengShiyingA/YingNode-Backend/main/install.sh) --uninstall
#
# What it does:
#   1. Detects OS and installs Python 3.10+, git, curl, qrencode
#   2. Clones the repo to /opt/yingnode-backend
#   3. Creates a virtualenv and pip-installs dependencies
#   4. Bootstraps a .env file (with a random admin password)
#   5. Writes a systemd unit that runs waitress on 127.0.0.1:5001
#      (override with YINGNODE_LISTEN_HOST=0.0.0.0 to expose publicly)
#   6. Starts the service and prints the pairing info for the iOS client
#      (Pair URL + ASCII QR code, ready to scan with the YingNode app)
#
# Safe to re-run — existing installs are upgraded in place, .env is preserved.

set -euo pipefail

REPO_URL="${YINGNODE_REPO_URL:-https://github.com/DengShiyingA/YingNode-Backend.git}"
REPO_BRANCH="${YINGNODE_REPO_BRANCH:-main}"
INSTALL_DIR="${YINGNODE_INSTALL_DIR:-/opt/yingnode-backend}"
SERVICE_NAME="yingnode-backend"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
LISTEN_HOST="${YINGNODE_LISTEN_HOST:-127.0.0.1}"
LISTEN_PORT="${YINGNODE_LISTEN_PORT:-5001}"

# ---- Colors ----------------------------------------------------------

if [ -t 1 ]; then
    C_RESET="\033[0m"
    C_BOLD="\033[1m"
    C_RED="\033[31m"
    C_GREEN="\033[32m"
    C_YELLOW="\033[33m"
    C_BLUE="\033[36m"
else
    C_RESET=""; C_BOLD=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""
fi

log()  { printf "${C_BLUE}[YingNode]${C_RESET} %s\n" "$*"; }
ok()   { printf "${C_GREEN}[  OK  ]${C_RESET} %s\n" "$*"; }
warn() { printf "${C_YELLOW}[WARN]${C_RESET} %s\n" "$*" >&2; }
die()  { printf "${C_RED}[ERROR]${C_RESET} %s\n" "$*" >&2; exit 1; }

# ---- Preflight -------------------------------------------------------

require_root() {
    if [ "${EUID:-$(id -u)}" -ne 0 ]; then
        die "please run as root (or with sudo)"
    fi
}

detect_pkg_mgr() {
    if command -v apt-get >/dev/null 2>&1; then echo apt; return; fi
    if command -v dnf     >/dev/null 2>&1; then echo dnf; return; fi
    if command -v yum     >/dev/null 2>&1; then echo yum; return; fi
    if command -v apk     >/dev/null 2>&1; then echo apk; return; fi
    die "unsupported package manager (need apt/dnf/yum/apk)"
}

install_system_deps() {
    local pkg_mgr="$1"
    log "installing system dependencies via ${pkg_mgr}"
    case "$pkg_mgr" in
        apt)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -y
            apt-get install -y python3 python3-venv python3-pip git curl qrencode ca-certificates
            ;;
        dnf)
            dnf install -y python3 python3-pip git curl qrencode ca-certificates
            ;;
        yum)
            yum install -y python3 python3-pip git curl qrencode ca-certificates
            ;;
        apk)
            apk add --no-cache python3 py3-pip py3-virtualenv git curl libqrencode-tools ca-certificates
            ;;
    esac
    ok "system deps installed"
}

check_python_version() {
    if ! command -v python3 >/dev/null 2>&1; then
        die "python3 not found after install"
    fi
    local ver
    ver="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
    local major minor
    IFS=. read -r major minor <<< "$ver"
    if [ "$major" -lt 3 ] || { [ "$major" -eq 3 ] && [ "$minor" -lt 9 ]; }; then
        die "Python 3.9+ required, found ${ver}"
    fi
    ok "python3 ${ver}"
}

# ---- Install / upgrade ----------------------------------------------

fetch_or_update_repo() {
    if [ -d "${INSTALL_DIR}/.git" ]; then
        log "updating existing install at ${INSTALL_DIR}"
        (
            cd "${INSTALL_DIR}"
            git fetch --depth=1 origin "${REPO_BRANCH}"
            git reset --hard "origin/${REPO_BRANCH}"
        )
    else
        log "cloning ${REPO_URL} (${REPO_BRANCH}) to ${INSTALL_DIR}"
        rm -rf "${INSTALL_DIR}"
        git clone --depth=1 -b "${REPO_BRANCH}" "${REPO_URL}" "${INSTALL_DIR}"
    fi
    ok "repo ready"
}

setup_venv() {
    log "creating python venv"
    if [ ! -d "${INSTALL_DIR}/venv" ]; then
        python3 -m venv "${INSTALL_DIR}/venv"
    fi
    "${INSTALL_DIR}/venv/bin/pip" install --upgrade pip >/dev/null
    log "installing python dependencies (may take a minute)"
    "${INSTALL_DIR}/venv/bin/pip" install -r "${INSTALL_DIR}/requirements.txt"
    ok "venv ready"
}

bootstrap_env_file() {
    local env_file="${INSTALL_DIR}/.env"
    if [ -f "$env_file" ]; then
        ok ".env already exists — preserved"
        return
    fi
    log "generating .env with a random admin password"

    local admin_password
    admin_password="$(head -c 18 /dev/urandom | base64 | tr -d '/+=' | head -c 18)"
    local secret_key
    secret_key="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"

    cat > "$env_file" <<EOF
# Auto-generated by install.sh on $(date -u '+%Y-%m-%d %H:%M:%S UTC')
# Back this file up — losing YINGNODE_SECRET_KEY makes stored VPS passwords
# unrecoverable.

YINGNODE_SECRET_KEY=${secret_key}
YINGNODE_ADMIN_USERNAME=admin
YINGNODE_ADMIN_PASSWORD=${admin_password}
YINGNODE_AUTH_REQUIRED=1

YINGNODE_HOST=${LISTEN_HOST}
YINGNODE_PORT=${LISTEN_PORT}
EOF
    chmod 600 "$env_file"
    ok ".env generated (admin password: ${admin_password})"
}

write_service_unit() {
    log "writing systemd unit ${SERVICE_FILE}"
    cat > "${SERVICE_FILE}" <<EOF
[Unit]
Description=YingNode Backend (Python Flask + sing-box control plane)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=${INSTALL_DIR}/.env
ExecStart=${INSTALL_DIR}/venv/bin/waitress-serve \\
    --host=${LISTEN_HOST} \\
    --port=${LISTEN_PORT} \\
    --threads=8 \\
    app:app
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    ok "systemd unit written"
}

start_service() {
    log "enabling and starting ${SERVICE_NAME}"
    systemctl enable "${SERVICE_NAME}" >/dev/null 2>&1 || true
    systemctl restart "${SERVICE_NAME}"

    # Wait for the HTTP listener to come up (up to 20 seconds)
    local i
    for i in $(seq 1 20); do
        if curl -fsS --max-time 2 "http://127.0.0.1:${LISTEN_PORT}/auth/pair" >/dev/null 2>&1; then
            ok "service is up (pid $(systemctl show -p MainPID --value ${SERVICE_NAME}))"
            return 0
        fi
        sleep 1
    done
    die "service did not start in time — check 'journalctl -u ${SERVICE_NAME} -n 50'"
}

# ---- Pairing banner --------------------------------------------------

fetch_pair_info() {
    local pair_json
    pair_json="$(curl -fsS --max-time 5 "http://127.0.0.1:${LISTEN_PORT}/auth/pair" || true)"
    if [ -z "$pair_json" ]; then
        warn "could not fetch /auth/pair; skipping pairing banner"
        return
    fi

    # Extract fields with simple grep rather than jq to avoid another dep.
    local token url host port
    token="$(echo "$pair_json" | grep -o '"token"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | sed 's/.*"\([^"]*\)"$/\1/')"
    url="$(echo "$pair_json" | grep -o '"url"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | sed 's/.*"\([^"]*\)"$/\1/')"

    # Derive the external host from the network config if possible.
    host="$(hostname -I 2>/dev/null | awk '{print $1}')"
    [ -z "$host" ] && host="$(curl -fsS --max-time 5 ifconfig.me 2>/dev/null || echo '<YOUR_VPS_IP>')"
    port="${LISTEN_PORT}"

    # Rewrite the URL to point at the real external host (the server's
    # /auth/pair response uses whatever the HTTP Host header was, which
    # for a localhost curl is 127.0.0.1 — not what we want to share).
    if [ -n "$token" ]; then
        url="yingnode://pair?host=${host}&port=${port}&token=${token}"
    fi

    echo
    printf "${C_BOLD}============================================================${C_RESET}\n"
    printf "${C_BOLD}  YingNode Backend installed — pair with your iOS client${C_RESET}\n"
    printf "${C_BOLD}============================================================${C_RESET}\n"
    printf "  Listen:       ${C_GREEN}http://%s:%s${C_RESET}\n" "$host" "$port"
    printf "  Admin user:   ${C_GREEN}admin${C_RESET}   (password in .env)\n"
    printf "  Auth mode:    ${C_GREEN}enforced${C_RESET} (set YINGNODE_AUTH_REQUIRED=0 to disable while migrating clients)\n"
    if [ -n "$token" ]; then
        printf "  Token:        ${C_GREEN}%s${C_RESET}\n" "$token"
        printf "  Pair URL:     ${C_GREEN}%s${C_RESET}\n" "$url"
        echo
        if command -v qrencode >/dev/null 2>&1; then
            printf "${C_BOLD}  Scan this with the YingNode iOS app:${C_RESET}\n\n"
            qrencode -t ANSIUTF8 -m 2 -- "$url"
            echo
        fi
    fi
    printf "${C_BOLD}============================================================${C_RESET}\n"
    printf "  Useful commands:\n"
    printf "    systemctl status  ${SERVICE_NAME}\n"
    printf "    systemctl restart ${SERVICE_NAME}\n"
    printf "    journalctl -u     ${SERVICE_NAME} -f\n"
    printf "    cat               ${INSTALL_DIR}/.env\n"
    printf "${C_BOLD}============================================================${C_RESET}\n"
    echo
}

# ---- Uninstall -------------------------------------------------------

uninstall() {
    log "uninstalling YingNode Backend"
    systemctl stop    "${SERVICE_NAME}" 2>/dev/null || true
    systemctl disable "${SERVICE_NAME}" 2>/dev/null || true
    rm -f "${SERVICE_FILE}"
    systemctl daemon-reload || true

    if [ -d "${INSTALL_DIR}" ]; then
        if [ -f "${INSTALL_DIR}/.env" ]; then
            local backup="/root/yingnode-backend.env.$(date +%s).bak"
            cp "${INSTALL_DIR}/.env" "$backup"
            warn "backed up .env to ${backup}"
        fi
        rm -rf "${INSTALL_DIR}"
    fi
    ok "uninstalled"
}

# ---- Main ------------------------------------------------------------

main() {
    require_root

    if [ "${1:-}" = "--uninstall" ] || [ "${1:-}" = "-u" ]; then
        uninstall
        exit 0
    fi

    local pkg_mgr
    pkg_mgr="$(detect_pkg_mgr)"

    install_system_deps "$pkg_mgr"
    check_python_version
    fetch_or_update_repo
    setup_venv
    bootstrap_env_file
    write_service_unit
    start_service
    fetch_pair_info
}

main "$@"
