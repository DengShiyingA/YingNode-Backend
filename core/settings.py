import json
import threading
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
SETTINGS_FILE = BASE_DIR / 'data' / 'settings.json'
_settings_lock = threading.RLock()
DEFAULT_SETTINGS = {
    'default_sni': 'www.yahoo.com',
    'default_singbox_version': '1.12.0',
    'panel_title': 'YingNode',
    'port_mode': 'random',
    'fixed_vless_port': '',
    'fixed_vmess_port': '',
    'fixed_hy2_port': '',
    'fixed_tuic_port': '',
    'fixed_trojan_port': '',
    'fixed_ss2022_port': '',
    'fixed_anytls_port': '',
    'fixed_naive_port': '',
    'fixed_wg_port': '',
    'fixed_shadowtls_port': '',
    'acme_mode': 'standalone',
    'acme_webroot': '',
    'cf_api_token': '',
    'ssh_auth_mode': 'auto',
    'ssh_private_key': '',
}


def _ensure_file():
    SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with _settings_lock:
        if not SETTINGS_FILE.exists():
            SETTINGS_FILE.write_text(json.dumps(DEFAULT_SETTINGS, ensure_ascii=False, indent=2), encoding='utf-8')


def load_settings():
    _ensure_file()
    with _settings_lock:
        try:
            data = json.loads(SETTINGS_FILE.read_text(encoding='utf-8'))
        except Exception:
            data = {}
    merged = DEFAULT_SETTINGS.copy()
    merged.update(data)
    return merged


def save_settings(patch: dict):
    with _settings_lock:
        current = load_settings()
        current.update({k: v for k, v in patch.items() if v is not None})
        SETTINGS_FILE.write_text(json.dumps(current, ensure_ascii=False, indent=2), encoding='utf-8')
    return current
