#!/usr/bin/env bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

log() { echo "[YingNode] $*"; }
die() { echo "[YingNode][ERROR] $*" >&2; exit 1; }

retry() {
  local tries="${1:-3}"; shift || true
  local n=1
  until "$@"; do
    if [[ "$n" -ge "$tries" ]]; then return 1; fi
    n=$((n+1))
    sleep 2
  done
}

require_root() {
  [[ "${EUID:-0}" -eq 0 ]] || die "请使用 root 运行脚本"
}

detect_pkg_mgr() {
  if command -v apt-get >/dev/null 2>&1; then PKG=apt; return; fi
  if command -v dnf >/dev/null 2>&1; then PKG=dnf; return; fi
  if command -v yum >/dev/null 2>&1; then PKG=yum; return; fi
  die "不支持当前系统包管理器"
}

install_deps() {
  log "安装依赖"
  case "$PKG" in
    apt)
      retry 3 apt-get update -y
      retry 3 apt-get install -y curl jq openssl tar ca-certificates socat iptables qrencode
      ;;
    dnf)
      retry 3 dnf install -y curl jq openssl tar ca-certificates socat iptables qrencode
      ;;
    yum)
      retry 3 yum install -y curl jq openssl tar ca-certificates socat iptables qrencode
      ;;
  esac
}

prepare_dirs() {
  mkdir -p /etc/s-box
}

check_systemd() {
  command -v systemctl >/dev/null 2>&1 || die "未检测到 systemd，无法自动部署"
}

detect_arch() {
  case "$(uname -m)" in
    x86_64) echo "amd64" ;;
    aarch64) echo "arm64" ;;
    *) die "不支持架构: $(uname -m)" ;;
  esac
}

port_in_use() {
  local p="$1"
  ss -lntup 2>/dev/null | grep -q ":${p} "
}

random_port() {
  local p
  for _ in $(seq 1 60); do
    p="$(shuf -i 20000-45000 -n 1)"
    if ! port_in_use "$p"; then echo "$p"; return 0; fi
  done
  echo "24443"
}

install_singbox() {
  local arch ver pkg url
  arch="$(detect_arch)"
  ver="${SINGBOX_VERSION:-1.12.0}"
  pkg="sing-box-${ver}-linux-${arch}"
  url="https://github.com/SagerNet/sing-box/releases/download/v${ver}/${pkg}.tar.gz"

  log "安装 sing-box v${ver}"
  retry 3 curl -fL --retry 3 --retry-delay 2 "$url" -o /tmp/sing-box.tgz
  tar xzf /tmp/sing-box.tgz -C /tmp
  install -m 755 "/tmp/${pkg}/sing-box" /etc/s-box/sing-box
  rm -rf "/tmp/${pkg}" /tmp/sing-box.tgz
}

install_cloudflared() {
  local arch url
  arch="$(detect_arch)"
  case "$arch" in
    amd64) url="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64" ;;
    arm64) url="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64" ;;
    *) die "不支持 cloudflared 架构: $(uname -m)" ;;
  esac

  log "安装 cloudflared"
  rm -f /etc/s-box/cloudflared
  retry 3 curl -fL --retry 3 --retry-delay 2 "$url" -o /etc/s-box/cloudflared
  chmod +x /etc/s-box/cloudflared
}

generate_materials() {
  log "生成密钥与基础参数"
  INSTALL_BUILD_AT="$(date '+%Y-%m-%d %H:%M:%S')"
  INSTALL_BUILD_VERSION="${SINGBOX_VERSION:-1.12.0}"
  UUID="$(/etc/s-box/sing-box generate uuid)"

  local kp
  kp="$(/etc/s-box/sing-box generate reality-keypair)"
  REALITY_PRIVATE="$(echo "$kp" | awk '/PrivateKey/ {print $2}' | tr -d '"')"
  REALITY_PUBLIC="$(echo "$kp" | awk '/PublicKey/ {print $2}' | tr -d '"')"
  SHORT_ID="$(openssl rand -hex 4)"

  SNI_DOMAIN="${SNI_DOMAIN:-www.yahoo.com}"
  SERVER_IP="$(curl -4 -s --max-time 10 ifconfig.me || hostname -I | awk '{print $1}')"

  VLESS_PORT="${VLESS_PORT:-$(random_port)}"
  VMESS_PORT="${VMESS_PORT:-$(random_port)}"
  HY2_PORT="${HY2_PORT:-$(random_port)}"
  TUIC_PORT="${TUIC_PORT:-$(random_port)}"
  TROJAN_PORT="${TROJAN_PORT:-$(random_port)}"
  SS2022_PORT="${SS2022_PORT:-$(random_port)}"
  ANYTLS_PORT="${ANYTLS_PORT:-$(random_port)}"

  SS2022_METHOD="${SS2022_METHOD:-2022-blake3-aes-128-gcm}"
  SS2022_PASSWORD="${SS2022_PASSWORD:-$(openssl rand -hex 16)}"
  VMESS_PATH="/${UUID}-vm"

  echo "$UUID" > /etc/s-box/uuid.txt
  echo "$REALITY_PRIVATE" > /etc/s-box/private_reality.key
  echo "$REALITY_PUBLIC" > /etc/s-box/public_reality.key
  echo "$SHORT_ID" > /etc/s-box/short_id.txt

  openssl ecparam -genkey -name prime256v1 -out /etc/s-box/private.key
  openssl req -new -x509 -days 3650 -key /etc/s-box/private.key -out /etc/s-box/cert.pem -subj "/CN=${SNI_DOMAIN}"
}

write_config() {
  log "写入 /etc/s-box/config.json"
  cat > /etc/s-box/config.json <<EOF
{
  "log": { "level": "info", "timestamp": true },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-reality-in",
      "listen": "::",
      "listen_port": ${VLESS_PORT},
      "users": [{ "uuid": "${UUID}", "flow": "xtls-rprx-vision" }],
      "tls": {
        "enabled": true,
        "server_name": "${SNI_DOMAIN}",
        "reality": {
          "enabled": true,
          "handshake": { "server": "${SNI_DOMAIN}", "server_port": 443 },
          "private_key": "${REALITY_PRIVATE}",
          "short_id": ["${SHORT_ID}"]
        }
      }
    },
    {
      "type": "vmess",
      "tag": "vmess-sb",
      "listen": "::",
      "listen_port": ${VMESS_PORT},
      "users": [{ "uuid": "${UUID}", "alterId": 0 }],
      "transport": {
        "type": "ws",
        "path": "${VMESS_PATH}",
        "headers": { "Host": "www.bing.com" }
      }
    },
    {
      "type": "hysteria2",
      "tag": "hy2-in",
      "listen": "::",
      "listen_port": ${HY2_PORT},
      "users": [{ "password": "${UUID}" }],
      "tls": {
        "enabled": true,
        "alpn": ["h3"],
        "certificate_path": "/etc/s-box/cert.pem",
        "key_path": "/etc/s-box/private.key"
      }
    },
    {
      "type": "tuic",
      "tag": "tuic-in",
      "listen": "::",
      "listen_port": ${TUIC_PORT},
      "users": [{ "uuid": "${UUID}", "password": "${UUID}" }],
      "congestion_control": "bbr",
      "tls": {
        "enabled": true,
        "alpn": ["h3"],
        "certificate_path": "/etc/s-box/cert.pem",
        "key_path": "/etc/s-box/private.key"
      }
    },
    {
      "type": "trojan",
      "tag": "trojan-in",
      "listen": "::",
      "listen_port": ${TROJAN_PORT},
      "users": [{ "name": "yingnode", "password": "${UUID}" }],
      "tls": {
        "enabled": true,
        "server_name": "${SNI_DOMAIN}",
        "certificate_path": "/etc/s-box/cert.pem",
        "key_path": "/etc/s-box/private.key"
      }
    },
    {
      "type": "shadowsocks",
      "tag": "ss2022-in",
      "listen": "::",
      "listen_port": ${SS2022_PORT},
      "method": "${SS2022_METHOD}",
      "password": "${SS2022_PASSWORD}"
    },
    {
      "type": "anytls",
      "tag": "anytls-in",
      "listen": "::",
      "listen_port": ${ANYTLS_PORT},
      "users": [{ "name": "yingnode", "password": "${UUID}" }],
      "tls": {
        "enabled": true,
        "server_name": "${SNI_DOMAIN}",
        "certificate_path": "/etc/s-box/cert.pem",
        "key_path": "/etc/s-box/private.key"
      }
    }
  ],
  "outbounds": [{ "type": "direct", "tag": "direct" }]
}
EOF
}

open_firewall_ports() {
  log "放行防火墙端口"
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
    ufw allow ${VLESS_PORT}/tcp || true
    ufw allow ${VMESS_PORT}/tcp || true
    ufw allow ${HY2_PORT}/udp || true
    ufw allow ${TUIC_PORT}/udp || true
    ufw allow ${TROJAN_PORT}/tcp || true
    ufw allow ${SS2022_PORT}/tcp || true
    ufw allow ${SS2022_PORT}/udp || true
    ufw allow ${ANYTLS_PORT}/tcp || true
  fi
  if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
    firewall-cmd --permanent --add-port=${VLESS_PORT}/tcp || true
    firewall-cmd --permanent --add-port=${VMESS_PORT}/tcp || true
    firewall-cmd --permanent --add-port=${HY2_PORT}/udp || true
    firewall-cmd --permanent --add-port=${TUIC_PORT}/udp || true
    firewall-cmd --permanent --add-port=${TROJAN_PORT}/tcp || true
    firewall-cmd --permanent --add-port=${SS2022_PORT}/tcp || true
    firewall-cmd --permanent --add-port=${SS2022_PORT}/udp || true
    firewall-cmd --permanent --add-port=${ANYTLS_PORT}/tcp || true
    firewall-cmd --reload || true
  fi
}

write_service() {
  log "写入 systemd 服务"
  cat > /etc/systemd/system/yingnode-sing-box.service <<'EOF'
[Unit]
Description=YingNode Sing-box Service
After=network.target

[Service]
Type=simple
ExecStart=/etc/s-box/sing-box run -c /etc/s-box/config.json
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable yingnode-sing-box.service
  systemctl restart yingnode-sing-box.service
}

write_outputs() {
  log "生成节点与客户端配置"

  cat > /etc/s-box/cert_info.json <<EOF
{
  "status": "ok",
  "days_left": 3650,
  "domain": "${SNI_DOMAIN}",
  "mode": "selfsigned",
  "message": "当前为自签证书，可后续切换 ACME。",
  "expire_at": ""
}
EOF

  cat > /etc/s-box/install_meta.json <<EOF
{
  "installer": "yingnode",
  "built_at": "${INSTALL_BUILD_AT}",
  "singbox_version": "${INSTALL_BUILD_VERSION}",
  "host_ip": "${SERVER_IP}",
  "sni_domain": "${SNI_DOMAIN}"
}
EOF

  cat > /etc/s-box/vl_reality.txt <<EOF
vless://${UUID}@${SERVER_IP}:${VLESS_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${SNI_DOMAIN}&fp=chrome&pbk=${REALITY_PUBLIC}&sid=${SHORT_ID}&type=tcp&headerType=none#YingNode-VLESS
EOF

  VMESS_JSON=$(printf '{"add":"%s","aid":"0","host":"www.bing.com","id":"%s","net":"ws","path":"%s","port":"%s","ps":"YingNode-VMESS-WS","type":"none","v":"2"}' "${SERVER_IP}" "${UUID}" "${VMESS_PATH}" "${VMESS_PORT}")
  printf 'vmess://%s\n' "$(printf '%s' "$VMESS_JSON" | base64 | tr -d '\n')" > /etc/s-box/vm_ws.txt

  cat > /etc/s-box/hy2.txt <<EOF
hysteria2://${UUID}@${SERVER_IP}:${HY2_PORT}?security=tls&alpn=h3&insecure=1&sni=${SNI_DOMAIN}#YingNode-HY2
EOF

  cat > /etc/s-box/tuic5.txt <<EOF
tuic://${UUID}:${UUID}@${SERVER_IP}:${TUIC_PORT}?congestion_control=bbr&alpn=h3&allow_insecure=1&sni=${SNI_DOMAIN}#YingNode-TUIC
EOF

  cat > /etc/s-box/trojan.txt <<EOF
trojan://${UUID}@${SERVER_IP}:${TROJAN_PORT}?security=tls&sni=${SNI_DOMAIN}&allowInsecure=1#YingNode-Trojan
EOF

  SS_B64="$(printf '%s:%s' "${SS2022_METHOD}" "${SS2022_PASSWORD}" | base64 | tr -d '\n=' | tr '+/' '-_')"
  cat > /etc/s-box/ss2022.txt <<EOF
ss://${SS_B64}@${SERVER_IP}:${SS2022_PORT}#YingNode-SS2022
EOF

  cat > /etc/s-box/an.txt <<EOF
anytls://${UUID}@${SERVER_IP}:${ANYTLS_PORT}?sni=${SNI_DOMAIN}&insecure=1#YingNode-AnyTLS
EOF

  cat > /etc/s-box/sing_box_client.json <<EOF
{
  "outbounds": [
    { "type": "selector", "tag": "proxy", "outbounds": ["vless", "vmess"] },
    { "type": "vless", "tag": "vless", "server": "${SERVER_IP}", "server_port": ${VLESS_PORT}, "uuid": "${UUID}" },
    { "type": "vmess", "tag": "vmess", "server": "${SERVER_IP}", "server_port": ${VMESS_PORT}, "uuid": "${UUID}" }
  ]
}
EOF

  cat > /etc/s-box/clash_meta_client.yaml <<EOF
proxies:
  - name: vless-reality
    type: vless
    server: ${SERVER_IP}
    port: ${VLESS_PORT}
    uuid: ${UUID}
    tls: true
    servername: ${SNI_DOMAIN}
    flow: xtls-rprx-vision
    reality-opts:
      public-key: ${REALITY_PUBLIC}
      short-id: ${SHORT_ID}
    client-fingerprint: chrome
proxy-groups:
  - name: 节点选择
    type: select
    proxies:
      - vless-reality
rules:
  - MATCH,节点选择
EOF
}

install_panel() {
  log "安装 YingNode 面板"

  # 安装 Python3 和 pip
  case "$PKG" in
    apt)
      retry 3 apt-get install -y python3 python3-pip python3-venv git
      ;;
    dnf)
      retry 3 dnf install -y python3 python3-pip git
      ;;
    yum)
      retry 3 yum install -y python3 python3-pip git
      ;;
  esac

  # 克隆或更新仓库
  if [[ -d /opt/yingnode ]]; then
    git -C /opt/yingnode pull --ff-only || true
  else
    retry 3 git clone https://github.com/DengShiyingA/YingNode-Backend.git /opt/yingnode
  fi

  # 安装 Python 依赖
  pip3 install --break-system-packages -r /opt/yingnode/requirements.txt

  # 放行面板端口
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
    ufw allow 5001/tcp || true
  fi
  if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
    firewall-cmd --permanent --add-port=5001/tcp || true
    firewall-cmd --reload || true
  fi

  # 写入 systemd 服务
  cat > /etc/systemd/system/yingnode-panel.service <<'EOF'
[Unit]
Description=YingNode Panel
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/yingnode
ExecStart=/usr/bin/python3 app.py
Restart=on-failure
RestartSec=3
Environment=FLASK_ENV=production

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable yingnode-panel.service
  systemctl restart yingnode-panel.service

  log "YingNode 面板已启动，端口 5001"
}

health_check() {
  log "执行健康检查"
  /etc/s-box/sing-box check -c /etc/s-box/config.json
  systemctl is-active --quiet yingnode-sing-box.service || die "sing-box 服务未启动"
}

main() {
  require_root
  check_systemd
  detect_pkg_mgr
  install_deps
  prepare_dirs
  install_singbox
  install_cloudflared
  generate_materials
  write_config
  open_firewall_ports
  write_service
  write_outputs
  install_panel
  health_check
  log "安装完成"
}

main "$@"
