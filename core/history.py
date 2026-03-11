import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


BASE_DIR = Path(__file__).resolve().parent.parent
HISTORY_FILE = BASE_DIR / 'data' / 'deploy_history.json'


def _ensure_file():
    HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
    if not HISTORY_FILE.exists():
        HISTORY_FILE.write_text('[]', encoding='utf-8')


def load_history() -> List[Dict[str, Any]]:
    _ensure_file()
    try:
        return json.loads(HISTORY_FILE.read_text(encoding='utf-8'))
    except Exception:
        return []


def save_entry(host: str, status: str, username: str = '', note: str = '', nodes: Optional[List[Dict[str, Any]]] = None, error: Optional[str] = None, ports: Optional[List[str]] = None, validation: Optional[Dict[str, Any]] = None):
    items = load_history()
    items.insert(0, {
        'id': uuid.uuid4().hex,
        'host': host,
        'username': username,
        'note': note,
        'status': status,
        'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'node_count': len(nodes or []),
        'nodes': nodes or [],
        'ports': ports or [],
        'validation': validation or {},
        'error': error or '',
    })
    items = items[:30]
    HISTORY_FILE.write_text(json.dumps(items, ensure_ascii=False, indent=2), encoding='utf-8')


SERVERS_FILE = BASE_DIR / 'data' / 'servers.json'

def _ensure_servers_file():
    SERVERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    if not SERVERS_FILE.exists():
        SERVERS_FILE.write_text('[]', encoding='utf-8')

def load_servers():
    _ensure_servers_file()
    try:
        return json.loads(SERVERS_FILE.read_text(encoding='utf-8'))
    except Exception:
        return []

def save_server(host: str, username: str, note: str = '', password: str = ''):
    items = load_servers()
    existing = next((x for x in items if x.get('host') == host and x.get('username') == username), None)
    if existing and not note:
        note = existing.get('note', '')
    if existing and not password:
        password = existing.get('password', '')
    items = [x for x in items if not (x.get('host') == host and x.get('username') == username)]
    history_meta = {}
    if existing:
        history_meta = {
            'last_connect_test': existing.get('last_connect_test', {}),
            'last_availability': existing.get('last_availability', {}),
        }
    items.insert(0, {'host': host, 'username': username, 'password': password, 'note': note, 'deployed': False, 'status': 'idle', **history_meta})
    items = items[:20]
    SERVERS_FILE.write_text(json.dumps(items, ensure_ascii=False, indent=2), encoding='utf-8')


def delete_server(host: str, username: str):
    items = load_servers()
    items = [x for x in items if not (x.get('host') == host and x.get('username') == username)]
    SERVERS_FILE.write_text(json.dumps(items, ensure_ascii=False, indent=2), encoding='utf-8')


def get_history_entry(entry_id: str):
    items = load_history()
    return next((x for x in items if x.get('id') == entry_id), None)


def delete_history_entry(entry_id: str):
    items = load_history()
    items = [x for x in items if x.get('id') != entry_id]
    HISTORY_FILE.write_text(json.dumps(items, ensure_ascii=False, indent=2), encoding='utf-8')


def delete_history_by_host(host: str):
    items = load_history()
    items = [x for x in items if x.get('host') != host]
    HISTORY_FILE.write_text(json.dumps(items, ensure_ascii=False, indent=2), encoding='utf-8')


def set_server_status(host: str, username: str, deployed: bool):
    items = load_servers()
    changed = False
    for item in items:
        if item.get('host') == host and item.get('username') == username:
            item['deployed'] = deployed
            item['status'] = 'deployed' if deployed else 'idle'
            changed = True
    if changed:
        SERVERS_FILE.write_text(json.dumps(items, ensure_ascii=False, indent=2), encoding='utf-8')


def update_server_runtime_status(host: str, username: str, status: str):
    items = load_servers()
    changed = False
    for item in items:
        if item.get('host') == host and item.get('username') == username:
            item['status'] = status
            item['deployed'] = (status == 'deployed')
            changed = True
    if changed:
        SERVERS_FILE.write_text(json.dumps(items, ensure_ascii=False, indent=2), encoding='utf-8')


def set_last_connect_test(host: str, username: str, ok: bool, summary: str):
    items = load_servers()
    changed = False
    payload = {
        'ok': bool(ok),
        'summary': summary,
        'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    }
    for item in items:
        if item.get('host') == host and item.get('username') == username:
            item['last_connect_test'] = payload
            changed = True
    if changed:
        SERVERS_FILE.write_text(json.dumps(items, ensure_ascii=False, indent=2), encoding='utf-8')


def set_last_availability(host: str, username: str, summary: Dict[str, Any]):
    items = load_servers()
    changed = False
    payload = {
        'summary': summary or {},
        'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    }
    for item in items:
        if item.get('host') == host and item.get('username') == username:
            item['last_availability'] = payload
            changed = True
    if changed:
        SERVERS_FILE.write_text(json.dumps(items, ensure_ascii=False, indent=2), encoding='utf-8')


def get_latest_ports_by_host(host: str):
    items = load_history()
    for item in items:
        if item.get('host') == host and item.get('ports'):
            return item.get('ports', [])
    return []


def _humanize_validation_issue(item: Dict[str, Any]) -> str:
    key = item.get('key') or ''
    label = item.get('label') or item.get('key') or '存在异常'
    port = item.get('port')
    mapping = {
        'service_active': 'sing-box 服务未正常运行',
        'config_exists': '主配置文件缺失',
        'binary_exists': 'sing-box 二进制不可执行',
        'vless_output': 'VLESS 节点文件未生成',
        'vmess_output': 'VMess 节点文件未生成',
        'hy2_output': 'HY2 节点文件未生成',
        'tuic_output': 'TUIC 节点文件未生成',
        'trojan_output': 'Trojan 节点文件未生成',
        'ss2022_output': 'SS2022 节点文件未生成',
        'singbox_output': 'Sing-box 配置未生成',
        'mihomo_output': 'Mihomo 配置未生成',
    }
    if key in {'vless_port_listening', 'vmess_port_listening', 'hy2_port_listening', 'tuic_port_listening', 'trojan_port_listening', 'ss2022_port_listening'} and port:
        proto = label.split(' ', 1)[0]
        return f'{proto} 端口 {port} 未监听'
    return mapping.get(key, f'{label}异常')


def summarize_validation_issue(validation: Optional[Dict[str, Any]], limit: int = 2) -> str:
    data = validation or {}
    checks = data.get('checks') or []
    priority = {
        'service_active': 1,
        'config_exists': 2,
        'binary_exists': 3,
        'vless_port_listening': 4,
        'vmess_port_listening': 4,
        'hy2_port_listening': 4,
        'tuic_port_listening': 4,
        'trojan_port_listening': 4,
        'ss2022_port_listening': 4,
        'vless_output': 5,
        'vmess_output': 5,
        'hy2_output': 5,
        'tuic_output': 5,
        'trojan_output': 5,
        'ss2022_output': 5,
        'singbox_output': 6,
        'mihomo_output': 6,
    }
    failed = sorted(
        [item for item in checks if not item.get('passed')],
        key=lambda item: (priority.get(item.get('key') or '', 99), item.get('label') or item.get('key') or ''),
    )
    if not failed:
        return ''
    parts = [_humanize_validation_issue(item) for item in failed[:max(1, limit)]]
    return '；'.join(parts)


def get_latest_validation_by_host(host: str):
    items = load_history()
    for item in items:
        if item.get('host') == host and item.get('validation'):
            return item.get('validation', {})
    return {}


def get_latest_warning_history_by_host(host: str):
    items = load_history()
    for item in items:
        validation = item.get('validation') or {}
        if item.get('host') == host and validation.get('total') and validation.get('ok') is False:
            return item
    return None


def get_latest_cert_history_by_host(host: str):
    items = load_history()
    for item in items:
        if item.get('host') == host and '证书切换' in (item.get('note') or ''):
            return item
    return None


def get_recent_cert_history_by_host(host: str, limit: int = 3):
    items = load_history()
    result = []
    for item in items:
        if item.get('host') == host and '证书切换' in (item.get('note') or ''):
            result.append(item)
            if len(result) >= limit:
                break
    return result
