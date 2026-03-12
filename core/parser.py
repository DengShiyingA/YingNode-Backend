NODE_FILES = {
    'VLESS Reality': '/etc/s-box/vl_reality.txt',
    'VMess WS': '/etc/s-box/vm_ws.txt',
    'Hysteria2': '/etc/s-box/hy2.txt',
    'TUIC v5': '/etc/s-box/tuic5.txt',
    'Trojan TLS': '/etc/s-box/trojan.txt',
    'Shadowsocks 2022': '/etc/s-box/ss2022.txt',
    'Anytls': '/etc/s-box/an.txt',
    'NaiveProxy': '/etc/s-box/naive.txt',
    'WireGuard': '/etc/s-box/wg.txt',
    'ShadowTLS v3': '/etc/s-box/shadowtls.txt',
    'Sing-box 配置': '/etc/s-box/sing_box_client.json',
    'Mihomo 配置': '/etc/s-box/clash_meta_client.yaml',
    '服务状态': '/etc/s-box/service_status.txt',
}


def extract_nodes(read_results: dict) -> list:
    nodes = []
    for name, content in read_results.items():
        text = (content or '').strip()
        if text:
            nodes.append({'name': name, 'content': text})
    return nodes
