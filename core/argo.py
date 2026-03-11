import base64
import json
import os
import re
import signal
import subprocess
import time
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / 'data'
ARGO_STATE_FILE = DATA_DIR / 'argo_state.json'
ARGO_LOG_FILE = DATA_DIR / 'argo.log'
ARGO_TEMP_PID_FILE = DATA_DIR / 'argo.pid'
ARGO_FIXED_DOMAIN_FILE = DATA_DIR / 'argo_domain.txt'
ARGO_FIXED_TOKEN_FILE = DATA_DIR / 'argo_token.txt'
SB_JSON_FILE = Path('/etc/s-box/config.json')

CLOUDFLARED_CANDIDATES = [
    '/etc/s-box/cloudflared',
    '/usr/local/bin/cloudflared',
    '/usr/bin/cloudflared',
]


def now_text():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


DEFAULT_STATE = {
    'enabled': False,
    'mode': 'none',
    'status': 'idle',
    'domain': '',
    'port': None,
    'updated_at': None,
    'message': 'Argo 未启用',
}


def ensure_data_dir():
    DATA_DIR.mkdir(parents=True, exist_ok=True)


def get_cloudflared_path():
    for path in CLOUDFLARED_CANDIDATES:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


def read_text(path, default=''):
    try:
        return Path(path).read_text(encoding='utf-8').strip()
    except Exception:
        return default


def write_text(path, content):
    ensure_data_dir()
    Path(path).write_text(content, encoding='utf-8')


def load_argo_state():
    ensure_data_dir()
    try:
        return json.loads(ARGO_STATE_FILE.read_text(encoding='utf-8'))
    except Exception:
        return DEFAULT_STATE.copy()


def save_argo_state(data):
    ensure_data_dir()
    ARGO_STATE_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')
    return data


def process_exists(pid):
    try:
        os.kill(int(pid), 0)
        return True
    except Exception:
        return False


def get_vmess_inbound():
    if not SB_JSON_FILE.exists():
        return None
    try:
        data = json.loads(SB_JSON_FILE.read_text(encoding='utf-8'))
    except Exception:
        return None

    for inbound in data.get('inbounds', []):
        if inbound.get('tag') == 'vmess-sb' or inbound.get('type') == 'vmess':
            return inbound
    return None


def get_vmess_port():
    inbound = get_vmess_inbound()
    if not inbound:
        return None
    return inbound.get('listen_port')


def parse_trycloudflare_domain(log_text):
    if not log_text:
        return None
    match = re.search(r'https://([a-zA-Z0-9.-]+\.trycloudflare\.com)', log_text)
    if match:
        return match.group(1)
    return None


def get_argo_status():
    state = load_argo_state()
    state['port'] = get_vmess_port()

    saved_domain = read_text(ARGO_FIXED_DOMAIN_FILE)
    saved_token = read_text(ARGO_FIXED_TOKEN_FILE)
    if saved_domain and not state.get('domain'):
        state['domain'] = saved_domain
    if saved_domain and saved_token and state.get('mode') == 'none':
        state['mode'] = 'fixed'

    if state.get('mode') in ('temporary', 'fixed'):
        pid = read_text(ARGO_TEMP_PID_FILE)
        if pid and process_exists(pid):
            state['enabled'] = True
            state['status'] = 'running'
        elif state.get('enabled'):
            state['status'] = 'idle'
            state['message'] = state.get('message') or 'Argo 进程当前未运行，请检查日志或重新启动。'
    return state


def stop_argo():
    pid = read_text(ARGO_TEMP_PID_FILE)
    if pid:
        try:
            os.kill(int(pid), signal.SIGTERM)
            time.sleep(1)
        except Exception:
            pass

    if ARGO_TEMP_PID_FILE.exists():
        ARGO_TEMP_PID_FILE.unlink(missing_ok=True)

    state = load_argo_state()
    state.update({
        'enabled': False,
        'status': 'idle',
        'updated_at': now_text(),
        'message': 'Argo 已停止',
    })
    save_argo_state(state)
    return state


def start_temporary_argo():
    ensure_data_dir()
    vmess_port = get_vmess_port()
    if not vmess_port:
        raise RuntimeError('当前未检测到 VMess 端口，暂时无法启用 Argo。请先完成部署。')

    cloudflared = get_cloudflared_path()
    if not cloudflared:
        raise RuntimeError('未检测到 cloudflared 组件，暂时无法启用 Argo。')

    stop_argo()

    with open(ARGO_LOG_FILE, 'w', encoding='utf-8') as log_fp:
        proc = subprocess.Popen(
            [
                cloudflared,
                'tunnel',
                '--url',
                f'https://localhost:{vmess_port}',
                '--no-tls-verify',
                '--edge-ip-version',
                'auto',
                '--no-autoupdate',
                '--protocol',
                'http2',
            ],
            stdout=log_fp,
            stderr=subprocess.STDOUT,
        )

    write_text(ARGO_TEMP_PID_FILE, str(proc.pid))

    domain = None
    for _ in range(10):
        time.sleep(1.5)
        domain = parse_trycloudflare_domain(read_text(ARGO_LOG_FILE))
        if domain:
            break

    state = {
        'enabled': True,
        'mode': 'temporary',
        'status': 'running' if domain else 'partial',
        'domain': domain or '',
        'port': vmess_port,
        'updated_at': now_text(),
        'message': '临时隧道已启动' if domain else '临时隧道已启动，但暂未解析到域名',
    }
    save_argo_state(state)
    return state


def start_fixed_argo(token, domain):
    ensure_data_dir()
    token = (token or '').strip()
    domain = (domain or '').strip()
    if not token or not domain:
        raise RuntimeError('请填写完整的 Argo Token 和固定域名。')

    vmess_port = get_vmess_port()
    if not vmess_port:
        raise RuntimeError('当前未检测到 VMess 端口，暂时无法启用 Argo。请先完成部署。')

    cloudflared = get_cloudflared_path()
    if not cloudflared:
        raise RuntimeError('未检测到 cloudflared 组件，暂时无法启用 Argo。')

    stop_argo()
    write_text(ARGO_FIXED_TOKEN_FILE, token)
    write_text(ARGO_FIXED_DOMAIN_FILE, domain)

    with open(ARGO_LOG_FILE, 'w', encoding='utf-8') as log_fp:
        proc = subprocess.Popen(
            [
                cloudflared,
                'tunnel',
                '--no-autoupdate',
                '--edge-ip-version',
                'auto',
                '--protocol',
                'http2',
                'run',
                '--token',
                token,
            ],
            stdout=log_fp,
            stderr=subprocess.STDOUT,
        )

    write_text(ARGO_TEMP_PID_FILE, str(proc.pid))
    time.sleep(2)
    running = process_exists(proc.pid)

    state = {
        'enabled': running,
        'mode': 'fixed',
        'status': 'running' if running else 'partial',
        'domain': domain,
        'port': vmess_port,
        'updated_at': now_text(),
        'message': '固定隧道已启动' if running else '固定隧道进程已尝试启动，但当前未确认持续运行，请查看日志。',
    }
    save_argo_state(state)
    return state


def reset_argo():
    stop_argo()
    for path in [ARGO_FIXED_DOMAIN_FILE, ARGO_FIXED_TOKEN_FILE, ARGO_LOG_FILE, ARGO_STATE_FILE]:
        try:
            Path(path).unlink(missing_ok=True)
        except Exception:
            pass
    return DEFAULT_STATE.copy() | {
        'port': get_vmess_port(),
        'updated_at': now_text(),
        'message': 'Argo 配置已清除',
    }


def read_argo_logs():
    return read_text(ARGO_LOG_FILE, '')


def build_argo_result():
    state = get_argo_status()
    if not state.get('enabled') or not state.get('domain'):
        return {
            'available': False,
            'reason': '当前未启用 Argo，暂时没有可交付的 Argo 节点结果。',
            'state': state,
        }

    inbound = get_vmess_inbound()
    if not inbound:
        return {
            'available': False,
            'reason': '当前安装器还没有产出 VMess-ws 配置，Argo 结果暂时只能显示状态，不能生成完整节点。',
            'state': state,
        }

    user = (inbound.get('users') or [{}])[0]
    transport = inbound.get('transport') or {}
    path = transport.get('path') or '/'
    uuid = user.get('uuid')
    if not uuid:
        return {
            'available': False,
            'reason': '当前 VMess 配置缺少 UUID，无法生成 Argo 节点。',
            'state': state,
        }

    payload = {
        'add': state['domain'],
        'aid': '0',
        'host': state['domain'],
        'id': uuid,
        'net': 'ws',
        'path': path,
        'port': '443',
        'ps': f"YingNode-Argo-{'fixed' if state.get('mode') == 'fixed' else 'temp'}",
        'tls': 'tls',
        'sni': state['domain'],
        'fp': 'chrome',
        'type': 'none',
        'v': '2',
    }
    vmess_link = 'vmess://' + base64.b64encode(json.dumps(payload, ensure_ascii=False).encode('utf-8')).decode('utf-8')

    return {
        'available': True,
        'state': state,
        'node': {
            'name': 'Argo VMess 节点',
            'content': vmess_link,
            'domain': state['domain'],
            'port': '443',
            'path': path,
            'mode': state.get('mode'),
        },
    }
