import base64
import json
import re
import shlex
import time
from core.ssh_client import SSHRunner

REMOTE_CONFIG = '/etc/s-box/config.json'
REMOTE_CLOUDFLARED = '/etc/s-box/cloudflared'
REMOTE_ARGO_LOG = '/etc/s-box/argo.log'
REMOTE_ARGO_PID = '/etc/s-box/argo.pid'
REMOTE_ARGO_STATE = '/etc/s-box/argo_state.json'
REMOTE_ARGO_DOMAIN = '/etc/s-box/argo_domain.txt'
REMOTE_ARGO_TOKEN = '/etc/s-box/argo_token.txt'


def _read_remote(runner: SSHRunner, path: str) -> str:
    q = shlex.quote(path)
    code, out, err = runner.run(f"test -f {q} && cat {q} || true")
    return out.strip() if code == 0 else ''


def _write_remote(runner: SSHRunner, path: str, content: str):
    # `path` is always one of the module-level REMOTE_* constants, but we
    # still refuse anything that isn't a plain POSIX path so a future caller
    # can't accidentally turn this into a Python-heredoc injection point.
    if not re.match(r'^/[A-Za-z0-9._/\-]+$', path):
        raise ValueError(f"refusing to write to unsafe remote path: {path!r}")
    payload = json.dumps(content)
    runner.run(f"python3 - <<'PY'\nfrom pathlib import Path\nPath({path!r}).write_text({payload}, encoding='utf-8')\nPY")


def _get_vmess_inbound_remote(runner: SSHRunner):
    text = _read_remote(runner, REMOTE_CONFIG)
    if not text:
        return None
    try:
        data = json.loads(text)
    except Exception:
        return None
    for inbound in data.get('inbounds', []):
        if inbound.get('tag') == 'vmess-sb' or inbound.get('type') == 'vmess':
            return inbound
    return None


def _get_pid_running(runner: SSHRunner):
    pid = _read_remote(runner, REMOTE_ARGO_PID)
    if not pid:
        return False
    # `pid` is read from a remote file and therefore attacker-influenceable
    # once the VPS is reachable; refuse anything that isn't a plain integer.
    if not re.match(r'^\d+$', pid.strip()):
        return False
    code, out, err = runner.run(f"kill -0 {int(pid)} >/dev/null 2>&1; echo $? || true")
    return (out or '').strip() == '0'


def _parse_trycloudflare_domain(log_text: str):
    if not log_text:
        return None
    match = re.search(r'https://([a-zA-Z0-9.-]+\.trycloudflare\.com)', log_text)
    return match.group(1) if match else None


def _argo_log_has_error(log_text: str) -> bool:
    if not log_text:
        return False
    lowered = log_text.lower()
    bad_signals = [
        'error',
        'failed',
        'unauthorized',
        'token is invalid',
        'authentication failed',
        'connection refused',
    ]
    return any(signal in lowered for signal in bad_signals)


def _fixed_log_looks_ready(log_text: str) -> bool:
    if not log_text:
        return False
    lowered = log_text.lower()
    good_signals = [
        'registered tunnel connection',
        'connection registered',
        'starting metrics server',
        'connected to',
    ]
    return any(signal in lowered for signal in good_signals)


def get_remote_argo_status(host: str, username: str, password: str):
    with SSHRunner(host, username, password) as runner:
        inbound = _get_vmess_inbound_remote(runner)
        vmess_port = inbound.get('listen_port') if inbound else None
        saved_domain = _read_remote(runner, REMOTE_ARGO_DOMAIN)
        saved_token = _read_remote(runner, REMOTE_ARGO_TOKEN)
        log_text = _read_remote(runner, REMOTE_ARGO_LOG)
        running = _get_pid_running(runner)
        parsed_domain = _parse_trycloudflare_domain(log_text) or ''
        if parsed_domain and not saved_domain:
            _write_remote(runner, REMOTE_ARGO_DOMAIN, parsed_domain)
            saved_domain = parsed_domain
        if saved_token:
            mode = 'fixed'
        elif saved_domain or running:
            mode = 'temporary'
        else:
            mode = 'none'
        return {
            'enabled': running,
            'mode': mode,
            'status': 'running' if running else 'idle',
            'domain': saved_domain,
            'port': vmess_port,
            'updated_at': None,
            'message': '远程 Argo 运行中。临时隧道适合快速测试，不保证速度与稳定性。' if running and mode == 'temporary' else ('远程 Argo 运行中' if running else '当前未检测到远程 Argo 进程'),
        }


def start_remote_temporary_argo(host: str, username: str, password: str, log=None):
    def emit(message: str):
        if log:
            log(message)

    with SSHRunner(host, username, password) as runner:
        emit('已连接远程服务器，开始检查 VMess 配置…')
        inbound = _get_vmess_inbound_remote(runner)
        if not inbound:
            raise RuntimeError('远程服务器未检测到 VMess 配置，暂时无法启用 Argo。')
        vmess_port = inbound.get('listen_port')
        if not vmess_port:
            raise RuntimeError('远程服务器未检测到 VMess 端口，暂时无法启用 Argo。')

        emit('已读取 VMess 入站，开始检查 cloudflared…')
        code, out, err = runner.run(f"test -x {REMOTE_CLOUDFLARED} && echo ok || true")
        if (out or '').strip() != 'ok':
            raise RuntimeError('远程服务器未检测到 cloudflared 组件。')

        running = _get_pid_running(runner)
        saved_domain = _read_remote(runner, REMOTE_ARGO_DOMAIN)
        log_text = _read_remote(runner, REMOTE_ARGO_LOG)
        log_healthy = not _argo_log_has_error(log_text)
        if running and saved_domain and log_healthy and _parse_trycloudflare_domain(log_text):
            emit('检测到临时隧道已在运行、日志正常且域名可快速确认，直接复用当前域名。')
            return {
                'enabled': True,
                'mode': 'temporary',
                'status': 'running',
                'domain': saved_domain,
                'port': vmess_port,
                'updated_at': None,
                'message': '已复用当前临时隧道',
            }
        if running and not saved_domain and log_healthy:
            emit('检测到临时隧道进程已在运行，正在快速补查域名…')
            domain = _parse_trycloudflare_domain(log_text) or ''
            if domain:
                _write_remote(runner, REMOTE_ARGO_DOMAIN, domain)
                return {
                    'enabled': True,
                    'mode': 'temporary',
                    'status': 'running',
                    'domain': domain,
                    'port': vmess_port,
                    'updated_at': None,
                    'message': '已补全当前临时隧道域名',
                }
            return {
                'enabled': True,
                'mode': 'temporary',
                'status': 'partial',
                'domain': '',
                'port': vmess_port,
                'updated_at': None,
                'message': '临时隧道进程已在运行，域名确认中',
            }
        if running and not log_healthy:
            emit('检测到现有临时隧道日志异常，本次将重新启动。')

        emit('正在清理旧的 Argo 进程…')
        runner.run(f"if [ -f {REMOTE_ARGO_PID} ]; then kill $(cat {REMOTE_ARGO_PID}) >/dev/null 2>&1 || true; rm -f {REMOTE_ARGO_PID}; fi")
        start_cmd = (
            f"rm -f {REMOTE_ARGO_DOMAIN}; "
            f"sh -c 'nohup {REMOTE_CLOUDFLARED} tunnel --url http://localhost:{vmess_port} "
            f"--edge-ip-version auto --no-autoupdate --protocol http2 "
            f"> {REMOTE_ARGO_LOG} 2>&1 < /dev/null & echo $! > {REMOTE_ARGO_PID}'"
        )
        emit('正在启动临时隧道进程…')
        runner.run(start_cmd, timeout=20)
        time.sleep(0.4)
        emit('临时隧道进程已拉起，域名将继续确认。')
        return {
            'enabled': True,
            'mode': 'temporary',
            'status': 'partial',
            'domain': '',
            'port': vmess_port,
            'updated_at': None,
            'message': '临时隧道进程已启动，域名确认中',
        }


def start_remote_fixed_argo(host: str, username: str, password: str, token: str, domain: str, log=None):
    def emit(message: str):
        if log:
            log(message)
    token = (token or '').strip()
    domain = (domain or '').strip()
    if not token or not domain:
        raise RuntimeError('请填写完整的固定域名和 Argo Token。')

    with SSHRunner(host, username, password) as runner:
        emit('已连接远程服务器，开始检查固定隧道条件…')
        inbound = _get_vmess_inbound_remote(runner)
        if not inbound:
            raise RuntimeError('远程服务器未检测到 VMess 配置，暂时无法启用固定 Argo。')
        vmess_port = inbound.get('listen_port')
        if not vmess_port:
            raise RuntimeError('远程服务器未检测到 VMess 端口，暂时无法启用固定 Argo。')

        emit('已读取 VMess 入站，开始检查 cloudflared…')
        code, out, err = runner.run(f"test -x {REMOTE_CLOUDFLARED} && echo ok || true")
        if (out or '').strip() != 'ok':
            raise RuntimeError('远程服务器未检测到 cloudflared 组件。')

        saved_domain = _read_remote(runner, REMOTE_ARGO_DOMAIN)
        saved_token = _read_remote(runner, REMOTE_ARGO_TOKEN)
        running = _get_pid_running(runner)
        log_text = _read_remote(runner, REMOTE_ARGO_LOG)
        log_healthy = not _argo_log_has_error(log_text)
        if running and saved_domain == domain and saved_token == token and log_healthy and _fixed_log_looks_ready(log_text):
            emit('检测到固定隧道已在运行、配置未变化且日志信号正常，直接复用当前状态。')
            return {
                'enabled': True,
                'mode': 'fixed',
                'status': 'running',
                'domain': domain,
                'port': vmess_port,
                'updated_at': None,
                'message': '已复用当前固定隧道',
            }
        if running and (not log_healthy or not _fixed_log_looks_ready(log_text)):
            emit('检测到现有固定隧道状态不够健康，本次将重新启动。')

        emit('正在写入固定域名和 Token…')
        _write_remote(runner, REMOTE_ARGO_DOMAIN, domain)
        _write_remote(runner, REMOTE_ARGO_TOKEN, token)
        emit('正在清理旧的 Argo 进程…')
        runner.run(f"if [ -f {REMOTE_ARGO_PID} ]; then kill $(cat {REMOTE_ARGO_PID}) >/dev/null 2>&1 || true; rm -f {REMOTE_ARGO_PID}; fi")
        start_cmd = (
            f"sh -c 'nohup {REMOTE_CLOUDFLARED} tunnel --no-autoupdate --edge-ip-version auto "
            f"--protocol http2 run --token {token} > {REMOTE_ARGO_LOG} 2>&1 < /dev/null & echo $! > {REMOTE_ARGO_PID}'"
        )
        emit('正在启动固定隧道进程…')
        runner.run(start_cmd, timeout=20)
        time.sleep(0.4)
        running = _get_pid_running(runner)
        return {
            'enabled': running,
            'mode': 'fixed',
            'status': 'running' if running else 'partial',
            'domain': domain,
            'port': vmess_port,
            'updated_at': None,
            'message': '远程固定隧道已启动' if running else '固定隧道已启动，正在后台继续确认状态。',
        }


def stop_remote_argo(host: str, username: str, password: str):
    with SSHRunner(host, username, password) as runner:
        runner.run(f"if [ -f {REMOTE_ARGO_PID} ]; then kill $(cat {REMOTE_ARGO_PID}) >/dev/null 2>&1 || true; rm -f {REMOTE_ARGO_PID}; fi")
        mode = 'fixed' if (_read_remote(runner, REMOTE_ARGO_TOKEN) and _read_remote(runner, REMOTE_ARGO_DOMAIN)) else 'none'
        return {
            'enabled': False,
            'mode': mode,
            'status': 'idle',
            'domain': _read_remote(runner, REMOTE_ARGO_DOMAIN),
            'port': (_get_vmess_inbound_remote(runner) or {}).get('listen_port'),
            'updated_at': None,
            'message': '远程 Argo 已停止',
        }


def reset_remote_argo(host: str, username: str, password: str):
    with SSHRunner(host, username, password) as runner:
        runner.run(f"if [ -f {REMOTE_ARGO_PID} ]; then kill $(cat {REMOTE_ARGO_PID}) >/dev/null 2>&1 || true; rm -f {REMOTE_ARGO_PID}; fi")
        runner.run(f"rm -f {REMOTE_ARGO_DOMAIN} {REMOTE_ARGO_TOKEN} {REMOTE_ARGO_LOG}")
        return {
            'enabled': False,
            'mode': 'none',
            'status': 'idle',
            'domain': '',
            'port': (_get_vmess_inbound_remote(runner) or {}).get('listen_port'),
            'updated_at': None,
            'message': '远程 Argo 配置已清除',
        }


def read_remote_argo_logs(host: str, username: str, password: str):
    with SSHRunner(host, username, password) as runner:
        return _read_remote(runner, REMOTE_ARGO_LOG)


def build_remote_argo_result(host: str, username: str, password: str):
    with SSHRunner(host, username, password) as runner:
        inbound = _get_vmess_inbound_remote(runner)
        vmess_port = inbound.get('listen_port') if inbound else None
        saved_domain = _read_remote(runner, REMOTE_ARGO_DOMAIN)
        saved_token = _read_remote(runner, REMOTE_ARGO_TOKEN)
        log_text = _read_remote(runner, REMOTE_ARGO_LOG)
        running = _get_pid_running(runner)
        parsed_domain = _parse_trycloudflare_domain(log_text) or ''
        if parsed_domain and not saved_domain:
            _write_remote(runner, REMOTE_ARGO_DOMAIN, parsed_domain)
            saved_domain = parsed_domain
        if saved_token:
            mode = 'fixed'
        elif saved_domain or running:
            mode = 'temporary'
        else:
            mode = 'none'
        state = {
            'enabled': running,
            'mode': mode,
            'status': 'running' if running else 'idle',
            'domain': saved_domain,
            'port': vmess_port,
            'updated_at': None,
            'message': '远程 Argo 运行中。临时隧道适合快速测试，不保证速度与稳定性。' if running and mode == 'temporary' else ('远程 Argo 运行中' if running else '当前未检测到远程 Argo 进程'),
        }
        if not state.get('enabled') or not state.get('domain'):
            return {
                'available': False,
                'reason': '当前未启用 Argo，暂时没有可交付的 Argo 节点结果。',
                'state': state,
            }

        if not inbound:
            return {
                'available': False,
                'reason': '当前未检测到 VMess 配置，暂时无法生成 Argo 节点。',
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
