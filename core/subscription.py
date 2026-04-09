from __future__ import annotations

import copy
import json
import re
import threading
import time
from typing import Dict, List

from flask import Response

from core.argo_remote import build_remote_argo_result
from core.ssh_client import SSHRunner

ARTIFACTS = [
    ('reality', 'VLESS Reality', 'uri', '/etc/s-box/vl_reality.txt'),
    ('vmess_ws', 'VMess WS', 'uri', '/etc/s-box/vm_ws.txt'),
    ('hy2', 'Hysteria2', 'uri', '/etc/s-box/hy2.txt'),
    ('tuic5', 'TUIC', 'uri', '/etc/s-box/tuic5.txt'),
    ('trojan', 'Trojan', 'uri', '/etc/s-box/trojan.txt'),
    ('ss2022', 'Shadowsocks 2022', 'uri', '/etc/s-box/ss2022.txt'),
    ('anytls', 'AnyTLS', 'uri', '/etc/s-box/an.txt'),
    ('singbox', 'sing-box', 'json', '/etc/s-box/sing_box_client.json'),
    ('clash_meta', 'Clash Meta', 'yaml', '/etc/s-box/clash_meta_client.yaml'),
    ('install_meta', '安装元信息', 'json', '/etc/s-box/install_meta.json'),
]

ARGO_ARTIFACT_KEY = 'argo_vmess'

_SUBSCRIPTION_CACHE: Dict[str, Dict] = {}
_SUBSCRIPTION_CACHE_LOCK = threading.Lock()
_SUBSCRIPTION_CACHE_TTL = 8.0


def _cache_key(host: str, username: str) -> str:
    return f'{host}::{username or "root"}'



def get_cached_subscription_snapshot(host: str, username: str):
    key = _cache_key(host, username)
    with _SUBSCRIPTION_CACHE_LOCK:
        current = _SUBSCRIPTION_CACHE.get(key)
        if not current:
            return None
        if time.time() - current.get('ts', 0) > _SUBSCRIPTION_CACHE_TTL:
            _SUBSCRIPTION_CACHE.pop(key, None)
            return None
        return copy.deepcopy(current.get('data'))



def set_cached_subscription_snapshot(host: str, username: str, data: Dict):
    key = _cache_key(host, username)
    with _SUBSCRIPTION_CACHE_LOCK:
        _SUBSCRIPTION_CACHE[key] = {'ts': time.time(), 'data': copy.deepcopy(data)}



def invalidate_subscription_snapshot(host: str = '', username: str = ''):
    with _SUBSCRIPTION_CACHE_LOCK:
        if host:
            _SUBSCRIPTION_CACHE.pop(_cache_key(host, username or 'root'), None)
            return
        _SUBSCRIPTION_CACHE.clear()



def read_remote_text_file(runner: SSHRunner, path: str):
    code, out, err = runner.run(f"test -f {path} && cat {path} || true", timeout=30)
    content = (out or '').strip()
    if code != 0:
        return False, '', (err or '读取失败').strip()
    if not content:
        return False, '', '文件不存在或内容为空'
    return True, content, ''



def read_server_subscription_artifacts(host: str, username: str, password: str) -> Dict:
    items: List[Dict] = []
    errors: List[str] = []
    with SSHRunner(host, username, password) as runner:
        for key, label, content_type, path in ARTIFACTS:
            ok, content, error = read_remote_text_file(runner, path)
            item = {
                'key': key,
                'label': label,
                'type': content_type,
                'available': ok,
                'content': content if ok else '',
                'source': path,
                'error': '' if ok else error,
            }
            items.append(item)
            if not ok and error:
                errors.append(f'{label}：{error}')

    try:
        argo_result = build_remote_argo_result(host, username, password)
        argo_node = argo_result.get('node') or {}
        argo_available = bool(argo_result.get('available') and argo_node.get('content'))
        items.append({
            'key': ARGO_ARTIFACT_KEY,
            'label': 'Argo VMess',
            'type': 'uri',
            'available': argo_available,
            'content': argo_node.get('content', '') if argo_available else '',
            'source': 'argo_runtime',
            'error': '' if argo_available else (argo_result.get('reason', '') or '当前未启用 Argo'),
            'meta': {
                'domain': argo_node.get('domain', ''),
                'port': argo_node.get('port', ''),
                'path': argo_node.get('path', '/'),
                'mode': argo_node.get('mode', ''),
            },
        })
        if not argo_available and argo_result.get('reason'):
            errors.append(f"Argo VMess：{argo_result.get('reason')}")
    except Exception as exc:
        items.append({
            'key': ARGO_ARTIFACT_KEY,
            'label': 'Argo VMess',
            'type': 'uri',
            'available': False,
            'content': '',
            'source': 'argo_runtime',
            'error': str(exc),
            'meta': {},
        })
        errors.append(f'Argo VMess：{str(exc)}')

    return {
        'ok': any(item.get('available') for item in items),
        'host': host,
        'items': items,
        'errors': errors,
    }



def build_server_subscription_snapshot(server: Dict, force_refresh: bool = False) -> Dict:
    host = (server or {}).get('host', '')
    username = (server or {}).get('username', '') or 'root'
    password = (server or {}).get('password', '') or ''
    name = (server or {}).get('note', '') or host
    if not host or not password:
        return {
            'host': host,
            'name': name,
            'deployed': False,
            'items': [],
            'available_count': 0,
            'source_summary': {'file': 0, 'runtime': 0},
            'errors': ['缺少连接凭据'],
        }
    if not force_refresh:
        cached = get_cached_subscription_snapshot(host, username)
        if cached:
            return cached
    raw = read_server_subscription_artifacts(host, username, password)
    items = []
    for item in raw.get('items', []):
        current = dict(item)
        current['server'] = {'host': host, 'name': name, 'username': username}
        current_source = current.get('source') or ''
        current['source_kind'] = 'runtime' if current_source == 'argo_runtime' else 'file'
        items.append(current)
    normalized_nodes = [normalize_subscription_node(item) for item in items]
    result = {
        'host': host,
        'name': name,
        'deployed': True,
        'items': items,
        'nodes': [node for node in normalized_nodes if node.get('available')],
        'available_count': sum(1 for item in items if item.get('available')),
        'source_summary': {
            'file': sum(1 for item in items if item.get('available') and item.get('source_kind') == 'file'),
            'runtime': sum(1 for item in items if item.get('available') and item.get('source_kind') == 'runtime'),
        },
        'errors': raw.get('errors', []),
    }
    set_cached_subscription_snapshot(host, username, result)
    return result



def normalize_subscription_node(item: Dict) -> Dict:
    server = item.get('server') or {}
    meta = item.get('meta') or {}
    source_kind = item.get('source_kind') or ('runtime' if item.get('source') == 'argo_runtime' else 'file')
    key = item.get('key') or ''
    label = item.get('label') or key or '未命名产物'
    content_type = item.get('type') or ''
    protocol_map = {
        'reality': 'vless-reality',
        'vmess_ws': 'vmess-ws',
        'hy2': 'hysteria2',
        'tuic5': 'tuic',
        'trojan': 'trojan',
        'ss2022': 'shadowsocks-2022',
        'anytls': 'anytls',
        'singbox': 'sing-box',
        'clash_meta': 'clash-meta',
        'install_meta': 'install-meta',
        'argo_vmess': 'argo-vmess',
    }
    protocol = protocol_map.get(key, key or 'unknown')
    transport = ''
    if protocol in {'vmess-ws', 'argo-vmess'}:
        transport = 'ws'
    elif protocol == 'vless-reality':
        transport = 'tcp'
    elif protocol in {'hysteria2', 'tuic'}:
        transport = 'udp'
    elif protocol == 'trojan':
        transport = 'tls'
    elif protocol == 'shadowsocks-2022':
        transport = 'tcp+udp'
    elif protocol == 'anytls':
        transport = 'tls'
    node_kind = 'config' if content_type in {'json', 'yaml'} else 'node'
    address = meta.get('domain') or server.get('host') or ''
    return {
        'id': f"{server.get('host') or 'unknown'}::{key or 'item'}",
        'key': key,
        'label': label,
        'protocol': protocol,
        'transport': transport,
        'node_kind': node_kind,
        'content_type': content_type,
        'available': bool(item.get('available')),
        'content': item.get('content') or '',
        'source': item.get('source') or '',
        'source_kind': source_kind,
        'server': {
            'host': server.get('host') or '',
            'name': server.get('name') or server.get('host') or '',
            'username': server.get('username') or 'root',
        },
        'address': address,
        'meta': {
            'domain': meta.get('domain', ''),
            'port': meta.get('port', ''),
            'path': meta.get('path', ''),
            'mode': meta.get('mode', ''),
        },
        'error': item.get('error') or '',
    }



def build_base_subscription_output(items: List[Dict]) -> str:
    chunks = []
    for item in items:
        if item.get('content_type') != 'uri' or not item.get('available') or not item.get('content'):
            continue
        server = item.get('server') or {}
        suffix = '（运行态）' if item.get('source_kind') == 'runtime' else ''
        title = f"# {server.get('name') or server.get('host') or '未命名服务器'} / {item.get('label') or item.get('key')}{suffix}"
        chunks.append(f"{title}\n{item.get('content', '').strip()}")
    return '\n\n'.join(chunks).strip()



def _safe_server_tag(server: Dict) -> str:
    value = (server or {}).get('name') or (server or {}).get('host') or 'server'
    return ''.join(ch if ch.isalnum() or ch in {'-', '_'} else '-' for ch in value).strip('-') or 'server'



def _rename_clash_meta_content(content: str, server: Dict) -> str:
    server_tag = _safe_server_tag(server)
    replacements = {
        '节点选择': f'{server_tag}-节点选择',
        'vless-reality': f'{server_tag}-vless-reality',
        'vmess-ws': f'{server_tag}-vmess-ws',
        'hysteria2': f'{server_tag}-hysteria2',
        'tuic': f'{server_tag}-tuic',
    }
    lines = []
    for raw in (content or '').splitlines():
        line = raw
        stripped = raw.strip()
        for old, new in replacements.items():
            if stripped in {f'- {old}', f'name: {old}', f'- MATCH,{old}'}:
                line = raw.replace(old, new)
                break
            if f'proxies:' in raw or 'type:' in raw or 'server:' in raw or 'port:' in raw:
                continue
            if f'- {old}' in raw or f'name: {old}' in raw or f'MATCH,{old}' in raw:
                line = raw.replace(old, new)
        lines.append(line)
    return '\n'.join(lines).strip()



def _parse_simple_clash_config(content: str) -> Dict:
    lines = (content or '').splitlines()
    mode = None
    current_proxy = None
    current_group = None
    proxies = []
    groups = []
    rules = []
    header = []
    for raw in lines:
        line = raw.rstrip('\n')
        stripped = line.strip()
        if not stripped:
            continue
        if line == 'proxies:':
            mode = 'proxies'
            current_proxy = None
            continue
        if line == 'proxy-groups:':
            mode = 'groups'
            current_group = None
            continue
        if line == 'rules:':
            mode = 'rules'
            continue
        if mode is None:
            header.append(line)
            continue
        if mode == 'proxies':
            if line.startswith('  - name: '):
                current_proxy = {'name': line.split(': ', 1)[1], 'lines': [line]}
                proxies.append(current_proxy)
            elif current_proxy:
                current_proxy['lines'].append(line)
            continue
        if mode == 'groups':
            if line.startswith('  - name: '):
                current_group = {'name': line.split(': ', 1)[1], 'lines': [line], 'proxies': []}
                groups.append(current_group)
            elif current_group:
                current_group['lines'].append(line)
                if line.startswith('      - '):
                    current_group['proxies'].append(line.split('- ', 1)[1].strip())
            continue
        if mode == 'rules' and stripped.startswith('- '):
            rules.append(stripped[2:])
    return {'header': header, 'proxies': proxies, 'groups': groups, 'rules': rules}



def build_singbox_subscription_output(items: List[Dict]) -> str:
    singbox_items = [item for item in items if item.get('key') == 'singbox' and item.get('available') and item.get('content')]
    if not singbox_items:
        return ''
    merged_outbounds = []
    merged_tags = []
    seen_tags = set()
    for item in singbox_items:
        server = item.get('server') or {}
        server_tag = _safe_server_tag(server)
        try:
            payload = json.loads(item.get('content') or '{}')
        except Exception:
            continue
        for outbound in payload.get('outbounds') or []:
            out_type = outbound.get('type')
            if out_type in {'selector', 'urltest', 'direct', 'block', 'dns'}:
                continue
            current = copy.deepcopy(outbound)
            tag = current.get('tag') or current.get('type') or 'node'
            unique_tag = f"{server_tag}-{tag}"
            current['tag'] = unique_tag
            if unique_tag in seen_tags:
                continue
            seen_tags.add(unique_tag)
            merged_outbounds.append(current)
            merged_tags.append(unique_tag)
    if not merged_outbounds:
        return ''
    config = {
        'log': {'level': 'info', 'timestamp': True},
        'dns': {
            'servers': [
                {'tag': 'remote-dns', 'address': 'https://1.1.1.1/dns-query', 'detour': 'proxy'},
                {'tag': 'local-dns', 'address': 'https://223.5.5.5/dns-query', 'detour': 'direct'},
                {'tag': 'fakeip-dns', 'address': 'fakeip'},
            ],
            'rules': [
                {'outbound': 'any', 'server': 'local-dns'},
                {'rule_set': 'geosite-cn', 'server': 'local-dns'},
                {'query_type': ['A', 'AAAA'], 'server': 'fakeip-dns'},
            ],
            'fakeip': {
                'enabled': True,
                'inet4_range': '198.18.0.0/15',
                'inet6_range': 'fc00::/18',
            },
            'strategy': 'prefer_ipv4',
            'independent_cache': True,
        },
        'inbounds': [
            {
                'type': 'tun',
                'tag': 'tun-in',
                'inet4_address': '172.19.0.1/30',
                'inet6_address': 'fdfe:dcba:9876::1/126',
                'auto_route': True,
                'strict_route': True,
                'sniff': True,
                'sniff_override_destination': True,
            },
        ],
        'outbounds': [
            {
                'type': 'selector',
                'tag': 'proxy',
                'default': 'auto' if len(merged_tags) > 1 else merged_tags[0],
                'outbounds': (['auto'] if len(merged_tags) > 1 else []) + merged_tags,
            },
            *([
                {
                    'type': 'urltest',
                    'tag': 'auto',
                    'outbounds': merged_tags,
                    'url': 'http://www.gstatic.com/generate_204',
                    'interval': '10m',
                }
            ] if len(merged_tags) > 1 else []),
            *merged_outbounds,
            {'type': 'direct', 'tag': 'direct'},
            {'type': 'block', 'tag': 'block'},
            {'type': 'dns', 'tag': 'dns-out'},
        ],
        'route': {
            'auto_detect_interface': True,
            'final': 'proxy',
            'rules': [
                {'protocol': 'dns', 'outbound': 'dns-out'},
                {'protocol': ['quic', 'stun'], 'outbound': 'block'},
                {'rule_set': ['geoip-cn', 'geosite-cn'], 'outbound': 'direct'},
                {'ip_is_private': True, 'outbound': 'direct'},
            ],
            'rule_set': [
                {
                    'type': 'remote',
                    'tag': 'geoip-cn',
                    'format': 'binary',
                    'url': 'https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs',
                    'download_detour': 'direct',
                },
                {
                    'type': 'remote',
                    'tag': 'geosite-cn',
                    'format': 'binary',
                    'url': 'https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs',
                    'download_detour': 'direct',
                },
            ],
        },
        'experimental': {
            'cache_file': {'enabled': True},
            'clash_api': {'external_controller': '127.0.0.1:9090'},
        },
    }
    return json.dumps(config, ensure_ascii=False, indent=2)



def build_clash_subscription_output(items: List[Dict]) -> str:
    clash_items = [item for item in items if item.get('key') == 'clash_meta' and item.get('available') and item.get('content')]
    if not clash_items:
        return ''
    normalized = []
    for item in clash_items:
        server = item.get('server') or {}
        renamed = _rename_clash_meta_content(item.get('content', ''), server)
        parsed = _parse_simple_clash_config(renamed)
        normalized.append((server, parsed))
    header = normalized[0][1].get('header') or ['port: 7890', 'allow-lan: true', 'mode: rule', 'log-level: info']
    all_proxies = []
    selector_nodes = []
    seen_proxy_names = set()
    for _server, parsed in normalized:
        for proxy in parsed.get('proxies') or []:
            name = proxy.get('name') or ''
            if not name or name in seen_proxy_names:
                continue
            seen_proxy_names.add(name)
            all_proxies.extend(proxy.get('lines') or [])
            selector_nodes.append(name)
    if not selector_nodes:
        return ''
    parts = []
    parts.extend(header)
    parts.append('')
    parts.append('proxies:')
    parts.extend(all_proxies)
    parts.append('')
    parts.append('proxy-groups:')
    parts.append('  - name: 节点选择')
    parts.append('    type: select')
    parts.append('    proxies:')
    parts.append('      - 自动选择')
    for name in selector_nodes:
        parts.append(f'      - {name}')
    parts.append('  - name: 自动选择')
    parts.append('    type: url-test')
    parts.append('    url: http://www.gstatic.com/generate_204')
    parts.append('    interval: 300')
    parts.append('    proxies:')
    for name in selector_nodes:
        parts.append(f'      - {name}')
    parts.append('')
    parts.append('rules:')
    parts.append('  - MATCH,节点选择')
    return '\n'.join(parts).strip()



def build_subscription_aggregate(servers: List[Dict], force_refresh: bool = False) -> Dict:
    included = []
    skipped_details = []
    all_items: List[Dict] = []
    skipped = 0
    for server in servers or []:
        host = server.get('host', '')
        name = server.get('note') or host
        username = server.get('username', '') or 'root'
        deployed = server.get('status') == 'deployed' or server.get('deployed')
        if not deployed:
            skipped += 1
            skipped_details.append({'host': host, 'name': name, 'username': username, 'reason': '未部署，暂不纳入订阅聚合'})
            continue
        if not server.get('password'):
            skipped += 1
            skipped_details.append({'host': host, 'name': name, 'username': username, 'reason': '缺少连接凭据，无法读取远端产物'})
            continue
        try:
            snapshot = build_server_subscription_snapshot(server, force_refresh=force_refresh)
        except Exception as exc:
            skipped += 1
            included.append({
                'host': host,
                'name': name,
                'deployed': True,
                'items': [],
                'available_count': 0,
                'source_summary': {'file': 0, 'runtime': 0},
                'errors': [str(exc)],
            })
            skipped_details.append({'host': host, 'name': name, 'username': username, 'reason': str(exc) or '读取订阅产物失败'})
            continue
        if snapshot.get('available_count', 0) <= 0:
            skipped += 1
            included.append(snapshot)
            skipped_details.append({'host': host, 'name': name, 'username': username, 'reason': (snapshot.get('errors') or ['当前未读取到可用产物'])[0]})
            continue
        included.append(snapshot)
        all_items.extend(snapshot.get('items', []))
    normalized_nodes = [normalize_subscription_node(item) for item in all_items]
    available_items = [item for item in normalized_nodes if item.get('available')]
    return {
        'ok': True,
        'servers': included,
        'nodes': available_items,
        'outputs': {
            'base': build_base_subscription_output(normalized_nodes),
            'singbox': build_singbox_subscription_output(normalized_nodes),
            'clash_meta': build_clash_subscription_output(normalized_nodes),
        },
        'stats': {
            'total_servers': len(servers or []),
            'included_servers': sum(1 for item in included if item.get('available_count', 0) > 0),
            'skipped_servers': skipped,
            'total_items': len(available_items),
            'file_items': sum(1 for item in available_items if item.get('source_kind') == 'file'),
            'runtime_items': sum(1 for item in available_items if item.get('source_kind') == 'runtime'),
        },
        'skipped': skipped_details,
    }



def build_subscription_download_response(content: str, output_type: str) -> Response:
    mapping = {
        'base': ('text/plain; charset=utf-8', 'yingnode-subscription.txt'),
        'singbox': ('application/json; charset=utf-8', 'yingnode-sing-box.json'),
        'clash_meta': ('text/yaml; charset=utf-8', 'yingnode-clash-meta.yaml'),
    }
    mime, filename = mapping.get(output_type, mapping['base'])
    return Response(
        content or '',
        mimetype=mime,
        headers={'Content-Disposition': f'attachment; filename={filename}'},
    )
