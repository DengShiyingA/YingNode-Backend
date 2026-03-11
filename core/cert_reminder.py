from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.history import load_servers
from core.cert_remote import build_remote_cert_status

BASE_DIR = Path(__file__).resolve().parent.parent
STATE_FILE = BASE_DIR / 'data' / 'cert_reminder_state.json'

RISK_ORDER = {
    'ok': 0,
    'watch_14': 1,
    'warn_7': 2,
    'urgent_3': 3,
    'expired': 4,
}


def _ensure_state_file():
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    if not STATE_FILE.exists():
        STATE_FILE.write_text('{}', encoding='utf-8')



def load_cert_reminder_state() -> Dict[str, Any]:
    _ensure_state_file()
    try:
        return json.loads(STATE_FILE.read_text(encoding='utf-8'))
    except Exception:
        return {}



def save_cert_reminder_state(data: Dict[str, Any]):
    _ensure_state_file()
    STATE_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')



def classify_cert_risk(cert: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    cert = cert or {}
    status = cert.get('status')
    days_left = cert.get('days_left')
    if status == 'expired' or (isinstance(days_left, int) and days_left < 0):
        return {'level': 'expired', 'label': '已过期', 'rank': RISK_ORDER['expired']}
    if status == 'expiring' and isinstance(days_left, int):
        if days_left <= 3:
            return {'level': 'urgent_3', 'label': '3 天内过期', 'rank': RISK_ORDER['urgent_3']}
        if days_left <= 7:
            return {'level': 'warn_7', 'label': '7 天内过期', 'rank': RISK_ORDER['warn_7']}
        if days_left <= 14:
            return {'level': 'watch_14', 'label': '14 天内到期', 'rank': RISK_ORDER['watch_14']}
    return {'level': 'ok', 'label': '正常', 'rank': RISK_ORDER['ok']}



def build_cert_risk_snapshot(expected_domain: str = '') -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    for server in load_servers():
        deployed = server.get('status') == 'deployed' or server.get('deployed')
        if not deployed or not server.get('host') or not server.get('password'):
            continue
        try:
            cert = build_remote_cert_status(server.get('host', ''), server.get('username', '') or 'root', server.get('password', ''), expected_domain=expected_domain)
        except Exception as exc:
            results.append({
                'host': server.get('host', ''),
                'username': server.get('username', '') or 'root',
                'note': server.get('note', '') or server.get('host', ''),
                'cert': None,
                'risk': {'level': 'error', 'label': '读取失败', 'rank': 0},
                'error': str(exc),
            })
            continue
        results.append({
            'host': server.get('host', ''),
            'username': server.get('username', '') or 'root',
            'note': server.get('note', '') or server.get('host', ''),
            'cert': cert,
            'risk': classify_cert_risk(cert),
            'error': '',
        })
    return results



def should_emit_cert_reminder(current: Dict[str, Any], previous: Optional[Dict[str, Any]]) -> bool:
    current_level = (current.get('risk') or {}).get('level', 'ok')
    if current_level not in {'watch_14', 'warn_7', 'urgent_3', 'expired'}:
        return False
    if not previous:
        return current_level in {'warn_7', 'urgent_3', 'expired'}
    prev_level = previous.get('last_level', 'ok')
    return RISK_ORDER.get(current_level, 0) > RISK_ORDER.get(prev_level, 0)



def build_cert_reminder_text(snapshot: Dict[str, Any]) -> str:
    risk = snapshot.get('risk') or {}
    cert = snapshot.get('cert') or {}
    title = snapshot.get('note') or snapshot.get('host') or '未命名服务器'
    days_left = cert.get('days_left')
    if risk.get('level') == 'expired':
        return f'证书提醒：{title} 当前证书已过期，建议立即重新签发或先切换到可用证书。'
    if risk.get('level') == 'urgent_3':
        return f'证书提醒：{title} 当前 3 天内过期，建议立即检查续期链路并尽快处理。'
    if risk.get('level') == 'warn_7':
        return f'证书提醒：{title} 当前 7 天内过期，建议本周内完成续期验证。'
    return f'证书提醒：{title} 当前 {days_left} 天内到期，建议提前检查续期链路。'



def pick_cert_reminder_candidate(expected_domain: str = '', state: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
    state = state or load_cert_reminder_state()
    snapshots = build_cert_risk_snapshot(expected_domain=expected_domain)
    candidates = sorted(
        [item for item in snapshots if (item.get('risk') or {}).get('level') in {'watch_14', 'warn_7', 'urgent_3', 'expired'}],
        key=lambda item: (-(item.get('risk') or {}).get('rank', 0), item.get('host') or ''),
    )
    for item in candidates:
        key = f"{item.get('host', '')}::{item.get('username', '')}"
        previous = (state.get('servers') or {}).get(key)
        if should_emit_cert_reminder(item, previous):
            item['state_key'] = key
            item['reminder_text'] = build_cert_reminder_text(item)
            return item
    return None



def mark_cert_reminder_sent(snapshot: Dict[str, Any], state: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    state = state or load_cert_reminder_state()
    servers = state.setdefault('servers', {})
    key = snapshot.get('state_key') or f"{snapshot.get('host', '')}::{snapshot.get('username', '')}"
    servers[key] = {
        'last_level': (snapshot.get('risk') or {}).get('level', 'ok'),
        'last_sent_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'host': snapshot.get('host', ''),
        'username': snapshot.get('username', ''),
        'note': snapshot.get('note', ''),
    }
    save_cert_reminder_state(state)
    return state
