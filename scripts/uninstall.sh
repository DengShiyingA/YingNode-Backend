#!/usr/bin/env bash
set -euo pipefail

log() { echo "[YingNode-Uninstall] $*"; }
die() { echo "[YingNode-Uninstall][ERROR] $*" >&2; exit 1; }

require_root() {
  [[ "${EUID:-0}" -eq 0 ]] || die "请使用 root 运行此脚本"
}

safe_systemctl() {
  command -v systemctl >/dev/null 2>&1 || return 0
  systemctl "$@" 2>/dev/null || true
}

remove_service() {
  log "停止并删除 yingnode-sing-box 服务"
  safe_systemctl stop yingnode-sing-box.service
  safe_systemctl disable yingnode-sing-box.service
  rm -f /etc/systemd/system/yingnode-sing-box.service
  safe_systemctl daemon-reload
  safe_systemctl reset-failed
}

remove_runtime_files() {
  log "清理运行文件与节点产物"
  rm -f /etc/s-box/sing-box
  rm -f /etc/s-box/config.json
  rm -f /etc/s-box/uuid.txt /etc/s-box/private_reality.key /etc/s-box/public_reality.key /etc/s-box/short_id.txt

  rm -f /etc/s-box/vl_reality.txt /etc/s-box/vm_ws.txt /etc/s-box/hy2.txt /etc/s-box/tuic5.txt
  rm -f /etc/s-box/trojan.txt /etc/s-box/ss2022.txt /etc/s-box/an.txt
  rm -f /etc/s-box/sing_box_client.json /etc/s-box/clash_meta_client.yaml
  rm -f /etc/s-box/cert_info.json /etc/s-box/install_meta.json /etc/s-box/service_status.txt

  # 保留证书与私钥，便于后续复用（若要彻底删除可手动清理）
  # /etc/s-box/cert.pem
  # /etc/s-box/private.key
}

remove_cloudflared_binary() {
  log "停止并清理 cloudflared 相关文件"
  safe_systemctl stop cloudflared.service
  rm -f /etc/s-box/argo.log /etc/s-box/argo.pid /etc/s-box/argo_state.json /etc/s-box/argo_domain.txt /etc/s-box/argo_token.txt
  if [[ -x /etc/s-box/cloudflared ]]; then
    rm -f /etc/s-box/cloudflared
  fi
}

remove_firewall_rules() {
  local VLESS_PORT="${1:-}" VMESS_PORT="${2:-}" HY2_PORT="${3:-}" TUIC_PORT="${4:-}" TROJAN_PORT="${5:-}" SS2022_PORT="${6:-}" ANYTLS_PORT="${7:-}"

  if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
    log "回收 firewalld 端口"
    [[ -n "$VLESS_PORT" ]] && firewall-cmd --permanent --remove-port=${VLESS_PORT}/tcp || true
    [[ -n "$VMESS_PORT" ]] && firewall-cmd --permanent --remove-port=${VMESS_PORT}/tcp || true
    [[ -n "$HY2_PORT" ]] && firewall-cmd --permanent --remove-port=${HY2_PORT}/udp || true
    [[ -n "$TUIC_PORT" ]] && firewall-cmd --permanent --remove-port=${TUIC_PORT}/udp || true
    [[ -n "$TROJAN_PORT" ]] && firewall-cmd --permanent --remove-port=${TROJAN_PORT}/tcp || true
    [[ -n "$SS2022_PORT" ]] && firewall-cmd --permanent --remove-port=${SS2022_PORT}/tcp || true
    [[ -n "$SS2022_PORT" ]] && firewall-cmd --permanent --remove-port=${SS2022_PORT}/udp || true
    [[ -n "$ANYTLS_PORT" ]] && firewall-cmd --permanent --remove-port=${ANYTLS_PORT}/tcp || true
    firewall-cmd --reload || true
  fi

  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
    log "回收 ufw 端口"
    [[ -n "$VLESS_PORT" ]] && ufw delete allow ${VLESS_PORT}/tcp || true
    [[ -n "$VMESS_PORT" ]] && ufw delete allow ${VMESS_PORT}/tcp || true
    [[ -n "$HY2_PORT" ]] && ufw delete allow ${HY2_PORT}/udp || true
    [[ -n "$TUIC_PORT" ]] && ufw delete allow ${TUIC_PORT}/udp || true
    [[ -n "$TROJAN_PORT" ]] && ufw delete allow ${TROJAN_PORT}/tcp || true
    [[ -n "$SS2022_PORT" ]] && ufw delete allow ${SS2022_PORT}/tcp || true
    [[ -n "$SS2022_PORT" ]] && ufw delete allow ${SS2022_PORT}/udp || true
    [[ -n "$ANYTLS_PORT" ]] && ufw delete allow ${ANYTLS_PORT}/tcp || true
  fi

  if command -v iptables >/dev/null 2>&1; then
    log "回收 iptables 规则"
    [[ -n "$VLESS_PORT" ]] && while iptables -C INPUT -p tcp --dport ${VLESS_PORT} -j ACCEPT 2>/dev/null; do iptables -D INPUT -p tcp --dport ${VLESS_PORT} -j ACCEPT || true; done
    [[ -n "$VMESS_PORT" ]] && while iptables -C INPUT -p tcp --dport ${VMESS_PORT} -j ACCEPT 2>/dev/null; do iptables -D INPUT -p tcp --dport ${VMESS_PORT} -j ACCEPT || true; done
    [[ -n "$HY2_PORT" ]] && while iptables -C INPUT -p udp --dport ${HY2_PORT} -j ACCEPT 2>/dev/null; do iptables -D INPUT -p udp --dport ${HY2_PORT} -j ACCEPT || true; done
    [[ -n "$TUIC_PORT" ]] && while iptables -C INPUT -p udp --dport ${TUIC_PORT} -j ACCEPT 2>/dev/null; do iptables -D INPUT -p udp --dport ${TUIC_PORT} -j ACCEPT || true; done
    [[ -n "$TROJAN_PORT" ]] && while iptables -C INPUT -p tcp --dport ${TROJAN_PORT} -j ACCEPT 2>/dev/null; do iptables -D INPUT -p tcp --dport ${TROJAN_PORT} -j ACCEPT || true; done
    [[ -n "$SS2022_PORT" ]] && while iptables -C INPUT -p tcp --dport ${SS2022_PORT} -j ACCEPT 2>/dev/null; do iptables -D INPUT -p tcp --dport ${SS2022_PORT} -j ACCEPT || true; done
    [[ -n "$SS2022_PORT" ]] && while iptables -C INPUT -p udp --dport ${SS2022_PORT} -j ACCEPT 2>/dev/null; do iptables -D INPUT -p udp --dport ${SS2022_PORT} -j ACCEPT || true; done
    [[ -n "$ANYTLS_PORT" ]] && while iptables -C INPUT -p tcp --dport ${ANYTLS_PORT} -j ACCEPT 2>/dev/null; do iptables -D INPUT -p tcp --dport ${ANYTLS_PORT} -j ACCEPT || true; done
  fi
}

uninstall_panel() {
  log "卸载 YingNode 面板"

  systemctl stop yingnode-panel.service 2>/dev/null || true
  systemctl disable yingnode-panel.service 2>/dev/null || true
  rm -f /etc/systemd/system/yingnode-panel.service
  systemctl daemon-reload

  rm -rf /opt/yingnode

  if command -v ufw >/dev/null 2>&1; then
    ufw delete allow 5001/tcp 2>/dev/null || true
  fi
  if command -v firewall-cmd >/dev/null 2>&1; then
    firewall-cmd --permanent --remove-port=5001/tcp 2>/dev/null || true
    firewall-cmd --reload 2>/dev/null || true
  fi

  log "YingNode 面板已卸载"
}

verify_cleanup() {
  log "验证卸载结果"

  if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet yingnode-sing-box.service; then
      die "服务仍在运行，卸载未完成"
    fi
  fi

  [[ ! -x /etc/s-box/sing-box ]] || die "sing-box 二进制仍存在"
  [[ ! -f /etc/s-box/config.json ]] || die "配置文件仍存在"

  log "卸载验证通过"
}

main() {
  require_root

  local VLESS_PORT="${1:-}"
  local VMESS_PORT="${2:-}"
  local HY2_PORT="${3:-}"
  local TUIC_PORT="${4:-}"
  local TROJAN_PORT="${5:-}"
  local SS2022_PORT="${6:-}"
  local ANYTLS_PORT="${7:-}"

  remove_service
  remove_runtime_files
  remove_cloudflared_binary
  remove_firewall_rules "$VLESS_PORT" "$VMESS_PORT" "$HY2_PORT" "$TUIC_PORT" "$TROJAN_PORT" "$SS2022_PORT" "$ANYTLS_PORT"
  uninstall_panel
  verify_cleanup

  log "YingNode 卸载完成"
}

main "$@"
