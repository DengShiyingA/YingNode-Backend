import os
import threading
import time
from flask import Flask, jsonify, render_template, request
from core.history import delete_history_by_host, delete_history_entry, delete_server, get_history_entry, get_latest_cert_history_by_host, get_latest_ports_by_host, get_latest_validation_by_host, get_latest_warning_history_by_host, get_recent_cert_history_by_host, load_history, load_servers, save_entry, save_server, set_last_availability, set_last_connect_test, set_server_status, summarize_validation_issue, update_server_runtime_status
from core.installer import deploy_to_server, summarize_ports, uninstall_from_server
from core.settings import load_settings, save_settings
from core.runtime import create_job, get_job
from core.argo import get_argo_status, start_temporary_argo, start_fixed_argo, stop_argo, reset_argo, read_argo_logs, build_argo_result
from core.argo_remote import get_remote_argo_status, start_remote_temporary_argo, start_remote_fixed_argo, stop_remote_argo, reset_remote_argo, read_remote_argo_logs
from core.cert_remote import build_remote_cert_status, check_remote_acme_ready, switch_remote_cert_mode, validate_remote_cert_switch
from core.cert_reminder import load_cert_reminder_state, mark_cert_reminder_sent, pick_cert_reminder_candidate
from core.subscription import build_server_subscription_snapshot, build_subscription_aggregate, build_subscription_download_response, invalidate_subscription_snapshot

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024
app.secret_key = os.environ.get('YINGNODE_SECRET_KEY') or os.urandom(32).hex()

_argo_status_cache = {}
_ARGO_STATUS_CACHE_TTL = 2.0
_cert_status_cache = {}
_CERT_STATUS_CACHE_TTL = 15.0


def humanize_error_message(exc) -> str:
    msg = str(exc or '').strip()
    low = msg.lower()
    if 'error reading ssh protocol banner' in low:
        return '[E_SSH_BANNER] SSH 握手失败：服务器没有及时返回 SSH 响应。建议检查 22 端口、防火墙和 SSH 服务状态。'
    if 'authentication failed' in low:
        return '[E_SSH_AUTH] SSH 认证失败：用户名/密码或密钥不匹配。建议先做连接测试并确认认证方式。'
    if 'timed out' in low or 'timeout' in low:
        return '[E_NET_TIMEOUT] 连接超时：服务器响应过慢，或网络/端口不可达。建议检查安全组、防火墙、线路。'
    if 'refused' in low:
        return '[E_CONN_REFUSED] 连接被拒绝：请检查 SSH 端口是否开启，或服务是否正常运行。'
    if 'name or service not known' in low or 'nodename nor servname provided' in low:
        return '[E_DNS_RESOLVE] 服务器地址解析失败：请检查 IP 或域名是否填写正确。'
    if 'address already in use' in low or 'port ' in low and 'in use' in low:
        return '[E_PORT_IN_USE] 端口冲突：目标端口已被占用。建议改用随机端口或调整固定端口配置。'
    if 'unknown inbound type' in low:
        return '[E_SINGBOX_INBOUND] 协议类型不被当前 sing-box 识别。建议升级 sing-box 版本后重试。'
    if 'too many certificates already issued' in low or 'new-certificates-per-exact-set-of-identifiers' in low or ('429' in low and 'acme' in low):
        return '[E_ACME_RATE_LIMIT] ACME 证书申请触发限流（429）。请按 retry-after 时间后再试，或改用 dns_cf。'
    if 'cloudflare api token is invalid' in low or 'invalid token' in low:
        return '[E_CF_TOKEN] Cloudflare Token 无效或权限不足。建议确认 Zone:Read + DNS:Edit 权限。'
    if 'systemctl' in low and ('not found' in low or 'no such file' in low):
        return '[E_INIT_SYSTEM] 目标系统缺少 systemd/systemctl，当前自动部署流程不支持。'
    if 'apt-get' in low or 'yum' in low or 'dnf' in low:
        return '[E_DEPENDENCY] 系统依赖安装失败。建议检查镜像源可达性后重试。'
    return msg or '[E_UNKNOWN] 操作失败'


def get_cached_cert_status(host: str, username: str, password: str, expected_domain: str = ''):
    key = f'{host}::{username or "root"}::{expected_domain or ""}'
    now = time.time()
    cached = _cert_status_cache.get(key)
    if cached and now - cached.get('ts', 0) <= _CERT_STATUS_CACHE_TTL:
        return cached.get('data')
    data = build_remote_cert_status(host, username, password, expected_domain=expected_domain)
    _cert_status_cache[key] = {'ts': now, 'data': data}
    return data


def apply_mock_cert_risk(servers):
    mock_profiles = [
        {'status': 'expiring', 'days_left': 14, 'message': '证书将在 14 天后过期，建议提前检查续期链路'},
        {'status': 'expiring', 'days_left': 7, 'message': '证书将在 7 天内过期，建议本周内处理'},
        {'status': 'expiring', 'days_left': 3, 'message': '证书将在 3 天内过期，风险很高，请尽快处理'},
        {'status': 'expired', 'days_left': -1, 'message': '证书已过期，请尽快重签'},
    ]
    deployed_servers = [item for item in servers if item.get('status') == 'deployed' or item.get('deployed')]
    for index, server in enumerate(deployed_servers[:len(mock_profiles)]):
        base = dict(server.get('cert') or {})
        profile = mock_profiles[index]
        base.update(profile)
        server['cert'] = base
    return servers


@app.route('/', methods=['GET'])
def index():
    servers = []
    settings = load_settings()
    default_sni = settings.get('default_sni', '')
    for item in load_servers():
        current = dict(item)
        current['validation'] = get_latest_validation_by_host(item.get('host', ''))
        current['validation_summary'] = summarize_validation_issue(current['validation'])
        warning_item = get_latest_warning_history_by_host(item.get('host', ''))
        current['warning_history_id'] = warning_item.get('id') if warning_item else ''
        cert_item = get_latest_cert_history_by_host(item.get('host', ''))
        current['cert_history_id'] = cert_item.get('id') if cert_item else ''
        current['cert_history_status'] = cert_item.get('status') if cert_item else ''
        current['cert_history_note'] = cert_item.get('note') if cert_item else ''
        current['cert_history_error'] = cert_item.get('error') if cert_item else ''
        current['cert_history_recent'] = get_recent_cert_history_by_host(item.get('host', ''), limit=3)
        current['cert'] = None
        try:
            deployed = current.get('status') == 'deployed' or current.get('deployed')
            if deployed and current.get('host') and current.get('password'):
                current['cert'] = get_cached_cert_status(current.get('host', ''), current.get('username', '') or 'root', current.get('password', ''), expected_domain=default_sni)
        except Exception:
            current['cert'] = None
        servers.append(current)
    if request.args.get('mock_cert_risk', '').strip() in {'1', 'true', 'yes'}:
        servers = apply_mock_cert_risk(servers)
    settings = dict(settings)
    if settings.get('cf_api_token'):
        settings['cf_api_token'] = ''
        settings['cf_api_token_configured'] = True
    else:
        settings['cf_api_token_configured'] = False
    if settings.get('ssh_private_key'):
        settings['ssh_private_key'] = ''
        settings['ssh_private_key_configured'] = True
    else:
        settings['ssh_private_key_configured'] = False
    return render_template('index.html', history=load_history(), servers=servers, settings=settings)






@app.route('/favicon.ico')
def favicon():
    return ('', 204)


@app.route('/uninstall/preview', methods=['POST'])
def uninstall_preview():
    host = request.form.get('host', '').strip()
    username = request.form.get('username', '').strip() or 'root'
    password = request.form.get('password', '')

    if not host or not username or not password:
        return jsonify({'ok': False, 'error': '请填写服务器地址、用户名、密码后再预览卸载内容。'}), 400

    try:
        from core.ssh_client import SSHRunner
        from core.installer import _extract_port

        cached_ports = get_latest_ports_by_host(host)
        with SSHRunner(host, username, password) as runner:
            code, out, err = runner.run('systemctl is-active yingnode-sing-box.service || true', timeout=30)
            service_active = (out or '').strip() == 'active'
            code2, out2, err2 = runner.run('test -d /etc/s-box && echo yes || true', timeout=30)
            has_dir = (out2 or '').strip() == 'yes'

            def read_remote(path):
                code, out, err = runner.run(f"test -f {path} && cat {path} || true")
                return out.strip() if code == 0 else ''

            vless = read_remote('/etc/s-box/vl_reality.txt')
            vmess = read_remote('/etc/s-box/vm_ws.txt')
            hy2 = read_remote('/etc/s-box/hy2.txt')
            tuic = read_remote('/etc/s-box/tuic5.txt')
            trojan = read_remote('/etc/s-box/trojan.txt')
            ss2022 = read_remote('/etc/s-box/ss2022.txt')
            anytls = read_remote('/etc/s-box/an.txt')
            naive = read_remote('/etc/s-box/naive.txt')
            wg = read_remote('/etc/s-box/wg.conf')
            shadowtls = read_remote('/etc/s-box/shadowtls.txt')

        ports = []
        vp = _extract_port(vless)
        mp = _extract_port(vmess)
        hp = _extract_port(hy2)
        tp = _extract_port(tuic)
        trp = _extract_port(trojan)
        sp = _extract_port(ss2022)
        ap = _extract_port(anytls)
        np = _extract_port(naive)
        wp = _extract_port(wg)
        stp = _extract_port(shadowtls)
        if vp: ports.append(f'{vp}/tcp')
        if mp: ports.append(f'{mp}/tcp')
        if hp: ports.append(f'{hp}/udp')
        if tp: ports.append(f'{tp}/udp')
        if trp: ports.append(f'{trp}/tcp')
        if sp: ports.append(f'{sp}/tcp+udp')
        if ap: ports.append(f'{ap}/tcp')
        if np: ports.append(f'{np}/tcp')
        if wp: ports.append(f'{wp}/udp')
        if stp: ports.append(f'{stp}/tcp')
        if not ports and cached_ports:
            ports = cached_ports

        installed = service_active or has_dir or bool(ports)
        if not installed:
            return jsonify({'ok': False, 'error': '没有检测到这台服务器上已安装的 YingNode 节点服务或端口，已阻止卸载。'}), 400

        return jsonify({'ok': True, 'ports': ports, 'cached': bool(cached_ports and not (vp or mp or hp or tp or trp or sp or ap or np or wp or stp)), 'installed': installed})
    except Exception as exc:
        return jsonify({'ok': False, 'error': str(exc)}), 500


@app.route('/uninstall', methods=['POST'])
def uninstall():
    host = request.form.get('host', '').strip()
    username = request.form.get('username', '').strip() or 'root'
    password = request.form.get('password', '')

    if not host or not username or not password:
        return jsonify({'ok': False, 'error': '请填写服务器地址、用户名、密码后再卸载。'}), 400

    job = create_job()

    def worker():
        job.status = 'running'
        try:
            result = uninstall_from_server(host=host, username=username, password=password, log=job.add_log)
            invalidate_subscription_snapshot(host, username)
            delete_history_by_host(host)
            set_server_status(host, username, False)
            job.result = result
            job.status = 'done'
        except Exception as exc:
            job.error = str(exc)
            job.add_log(f'卸载失败：{exc}')
            job.status = 'error'

    threading.Thread(target=worker, daemon=True).start()
    return jsonify({'ok': True, 'job_id': job.id})






@app.route('/settings', methods=['POST'])
def update_settings():
    payload = {
        'default_sni': request.form.get('default_sni', '').strip() or None,
        'default_singbox_version': request.form.get('default_singbox_version', '').strip() or None,
        'panel_title': request.form.get('panel_title', '').strip() or None,
        'port_mode': request.form.get('port_mode', '').strip() or None,
        'fixed_vless_port': request.form.get('fixed_vless_port', '').strip() or '',
        'fixed_vmess_port': request.form.get('fixed_vmess_port', '').strip() or '',
        'fixed_hy2_port': request.form.get('fixed_hy2_port', '').strip() or '',
        'fixed_tuic_port': request.form.get('fixed_tuic_port', '').strip() or '',
        'fixed_trojan_port': request.form.get('fixed_trojan_port', '').strip() or '',
        'fixed_ss2022_port': request.form.get('fixed_ss2022_port', '').strip() or '',
        'fixed_anytls_port': request.form.get('fixed_anytls_port', '').strip() or '',
        'acme_mode': request.form.get('acme_mode', '').strip() or 'standalone',
        'acme_webroot': request.form.get('acme_webroot', '').strip() or '',
        'cf_api_token': request.form.get('cf_api_token', '').strip() or None,
        'ssh_auth_mode': request.form.get('ssh_auth_mode', '').strip() or 'auto',
        'ssh_private_key': request.form.get('ssh_private_key', '') or None,
    }
    data = save_settings(payload)
    return jsonify({'ok': True, 'settings': data})


def _get_remote_server_payload():
    host = request.values.get('host', '').strip()
    username = request.values.get('username', '').strip() or 'root'
    password = request.values.get('password', '')
    if not host or not username or not password:
        raise ValueError('请先填写服务器地址、用户名和密码。')
    return host, username, password


def ensure_server_deployed(host: str, username: str):
    for item in load_servers():
        if item.get('host') == host and (item.get('username') or 'root') == (username or 'root'):
            if item.get('status') == 'deployed' or item.get('deployed'):
                return True
            raise ValueError('当前服务器尚未完成节点部署，请先部署后再管理证书或隧道。')
    raise ValueError('当前服务器未保存到列表，或尚未完成节点部署。')


@app.route('/argo/status', methods=['POST'])
def argo_status():
    try:
        host, username, password = _get_remote_server_payload()
        ensure_server_deployed(host, username)
        cache_key = (host, username, password)
        now = time.time()
        cached = _argo_status_cache.get(cache_key)
        if cached and now - cached['ts'] < _ARGO_STATUS_CACHE_TTL:
            return jsonify({'ok': True, 'state': cached['state']})
        state = get_remote_argo_status(host, username, password)
        _argo_status_cache[cache_key] = {'ts': now, 'state': state}
        return jsonify({'ok': True, 'state': state})
    except Exception as exc:
        return jsonify({'ok': False, 'error': humanize_error_message(exc), 'state': {'enabled': False, 'status': 'disabled'}})


@app.route('/argo/temp', methods=['POST'])
def argo_temp():
    try:
        host, username, password = _get_remote_server_payload()
        ensure_server_deployed(host, username)
    except Exception as exc:
        return jsonify({'ok': False, 'error': str(exc)}), 400

    job = create_job()
    _argo_status_cache[(host, username, password)] = {
        'ts': time.time(),
        'state': {
            'enabled': True,
            'mode': 'temporary',
            'status': 'partial',
            'domain': '',
            'port': None,
            'updated_at': None,
            'message': '已发起临时隧道启动，正在后台执行…',
        }
    }

    def worker():
        job.status = 'running'
        try:
            state = start_remote_temporary_argo(host, username, password, log=job.add_log)
            _argo_status_cache[(host, username, password)] = {'ts': time.time(), 'state': state}
            job.result = {'state': state}
            job.status = 'done'
        except Exception as exc:
            job.error = humanize_error_message(exc)
            job.add_log(f'Argo 临时隧道启动失败：{job.error}')
            job.status = 'error'

    threading.Thread(target=worker, daemon=True).start()
    return jsonify({'ok': True, 'job_id': job.id})


@app.route('/argo/fixed', methods=['POST'])
def argo_fixed():
    try:
        host, username, password = _get_remote_server_payload()
        ensure_server_deployed(host, username)
        token = request.form.get('token', '')
        domain = request.form.get('domain', '')
    except Exception as exc:
        return jsonify({'ok': False, 'error': str(exc)}), 400

    job = create_job()
    _argo_status_cache[(host, username, password)] = {
        'ts': time.time(),
        'state': {
            'enabled': True,
            'mode': 'fixed',
            'status': 'partial',
            'domain': domain,
            'port': None,
            'updated_at': None,
            'message': '已发起固定隧道启动，正在后台执行…',
        }
    }

    def worker():
        job.status = 'running'
        try:
            state = start_remote_fixed_argo(host, username, password, token, domain, log=job.add_log)
            _argo_status_cache[(host, username, password)] = {'ts': time.time(), 'state': state}
            job.result = {'state': state}
            job.status = 'done'
        except Exception as exc:
            job.error = humanize_error_message(exc)
            job.add_log(f'Argo 固定隧道启动失败：{job.error}')
            job.status = 'error'

    threading.Thread(target=worker, daemon=True).start()
    return jsonify({'ok': True, 'job_id': job.id})


@app.route('/argo/stop', methods=['POST'])
def argo_stop():
    try:
        host, username, password = _get_remote_server_payload()
        ensure_server_deployed(host, username)
        state = stop_remote_argo(host, username, password)
        _argo_status_cache[(host, username, password)] = {'ts': time.time(), 'state': state}
        return jsonify({'ok': True, 'state': state})
    except Exception as exc:
        return jsonify({'ok': False, 'error': humanize_error_message(exc)}), 400


@app.route('/argo/reset', methods=['POST'])
def argo_reset():
    try:
        host, username, password = _get_remote_server_payload()
        ensure_server_deployed(host, username)
        state = reset_remote_argo(host, username, password)
        _argo_status_cache[(host, username, password)] = {'ts': time.time(), 'state': state}
        return jsonify({'ok': True, 'state': state})
    except Exception as exc:
        return jsonify({'ok': False, 'error': humanize_error_message(exc)}), 400


@app.route('/argo/logs', methods=['POST'])
def argo_logs():
    try:
        host, username, password = _get_remote_server_payload()
        ensure_server_deployed(host, username)
        return jsonify({'ok': True, 'logs': read_remote_argo_logs(host, username, password)})
    except Exception as exc:
        return jsonify({'ok': False, 'error': humanize_error_message(exc)}), 400


@app.route('/argo/result', methods=['GET'])
def argo_result():
    return jsonify({'ok': True, 'result': build_argo_result()})


@app.route('/subscription/server', methods=['GET'])
def subscription_server():
    try:
        host = request.args.get('host', '').strip()
        username = request.args.get('username', '').strip() or 'root'
        if not host:
            return jsonify({'ok': False, 'error': '缺少 host'}), 400
        ensure_server_deployed(host, username)
        server = next((item for item in load_servers() if item.get('host') == host and (item.get('username') or 'root') == username), None)
        if not server:
            return jsonify({'ok': False, 'error': '服务器不存在'}), 404
        force_refresh = request.args.get('refresh', '').strip() in {'1', 'true', 'yes'}
        snapshot = build_server_subscription_snapshot(server, force_refresh=force_refresh)
        return jsonify({'ok': True, 'server': {'host': snapshot.get('host', ''), 'name': snapshot.get('name', ''), 'deployed': True}, 'items': snapshot.get('items', []), 'nodes': snapshot.get('nodes', []), 'source_summary': snapshot.get('source_summary', {'file': 0, 'runtime': 0}), 'errors': snapshot.get('errors', [])})
    except Exception as exc:
        return jsonify({'ok': False, 'error': humanize_error_message(exc)}), 400


@app.route('/subscription/aggregate', methods=['GET'])
def subscription_aggregate():
    try:
        force_refresh = request.args.get('refresh', '').strip() in {'1', 'true', 'yes'}
        result = build_subscription_aggregate(load_servers(), force_refresh=force_refresh)
        return jsonify(result)
    except Exception as exc:
        return jsonify({'ok': False, 'error': humanize_error_message(exc)}), 400


@app.route('/subscription/download', methods=['GET'])
def subscription_download():
    try:
        output_type = request.args.get('type', 'base').strip() or 'base'
        result = build_subscription_aggregate(load_servers())
        content = (result.get('outputs') or {}).get(output_type, '')
        return build_subscription_download_response(content, output_type)
    except Exception as exc:
        return jsonify({'ok': False, 'error': humanize_error_message(exc)}), 400


@app.route('/cert/reminder/check', methods=['GET', 'POST'])
def cert_reminder_check():
    try:
        settings = load_settings()
        state = load_cert_reminder_state()
        candidate = pick_cert_reminder_candidate(expected_domain=settings.get('default_sni', ''), state=state)
        if not candidate:
            return jsonify({'ok': True, 'due': False, 'message': ''})
        auto_mark = request.values.get('mark_sent', '').strip() in {'1', 'true', 'yes'}
        if auto_mark:
            mark_cert_reminder_sent(candidate, state=state)
        return jsonify({
            'ok': True,
            'due': True,
            'message': candidate.get('reminder_text', ''),
            'snapshot': {
                'host': candidate.get('host', ''),
                'username': candidate.get('username', ''),
                'note': candidate.get('note', ''),
                'risk': candidate.get('risk', {}),
                'cert': candidate.get('cert', {}),
            },
            'marked': auto_mark,
        })
    except Exception as exc:
        return jsonify({'ok': False, 'error': humanize_error_message(exc)}), 400


@app.route('/cert/reminder/heartbeat', methods=['GET', 'POST'])
def cert_reminder_heartbeat():
    try:
        settings = load_settings()
        state = load_cert_reminder_state()
        candidate = pick_cert_reminder_candidate(expected_domain=settings.get('default_sni', ''), state=state)
        if not candidate:
            return jsonify({'ok': True, 'due': False, 'message': '', 'heartbeat_text': ''})
        mark_cert_reminder_sent(candidate, state=state)
        return jsonify({
            'ok': True,
            'due': True,
            'message': candidate.get('reminder_text', ''),
            'heartbeat_text': candidate.get('reminder_text', ''),
            'snapshot': {
                'host': candidate.get('host', ''),
                'username': candidate.get('username', ''),
                'note': candidate.get('note', ''),
                'risk': candidate.get('risk', {}),
                'cert': candidate.get('cert', {}),
            },
            'marked': True,
        })
    except Exception as exc:
        return jsonify({'ok': False, 'error': humanize_error_message(exc)}), 400


@app.route('/cert/status', methods=['POST'])
def cert_status():
    try:
        host, username, password = _get_remote_server_payload()
        ensure_server_deployed(host, username)
        settings = load_settings()
        cert = build_remote_cert_status(host, username, password, expected_domain=settings.get('default_sni', ''))
        _cert_status_cache[f'{host}::{username or "root"}::{settings.get("default_sni", "") or ""}'] = {'ts': time.time(), 'data': cert}
        return jsonify({'ok': True, 'cert': cert})
    except Exception as exc:
        return jsonify({'ok': False, 'error': humanize_error_message(exc)}), 400


@app.route('/cert/switch', methods=['POST'])
def cert_switch():
    try:
        host, username, password = _get_remote_server_payload()
        ensure_server_deployed(host, username)
        mode = request.form.get('mode', '').strip()
        if mode not in {'selfsigned', 'acme'}:
            return jsonify({'ok': False, 'error': '证书模式无效'}), 400
        settings = load_settings()
        expected_domain = settings.get('default_sni', '')
        acme_mode = settings.get('acme_mode', 'standalone') or 'standalone'
        acme_webroot = settings.get('acme_webroot', '') or ''
        cf_api_token = settings.get('cf_api_token', '') or ''
        job = create_job()

        def worker():
            job.status = 'running'
            try:
                if mode == 'acme':
                    job.add_log('开始 ACME 前置检查')
                    precheck = check_remote_acme_ready(host, username, password, expected_domain=expected_domain, acme_mode=acme_mode, acme_webroot=acme_webroot, cf_api_token=cf_api_token)
                    job.result = {'mode': mode, **precheck}
                    if not precheck.get('ok'):
                        save_entry(host=host, username=username, note=f"证书切换 · ACME（{acme_mode}）前置检查", status='error', error=precheck.get('message', ''), validation={'ok': False, 'checks': precheck.get('checks', []), 'message': precheck.get('message', ''), 'total': len(precheck.get('checks', [])), 'passed_count': sum(1 for x in precheck.get('checks', []) if x.get('passed'))})
                        job.add_log(precheck.get('message', 'ACME 前置检查未通过'))
                        job.status = 'done'
                        return
                    job.add_log('ACME 前置检查通过，开始正式切换')
                else:
                    job.result = {'mode': mode}
                    job.add_log('开始自签证书切换')

                def on_cert_progress(payload):
                    current = dict(job.result or {})
                    current.update(payload or {})
                    job.result = current
                    if payload and payload.get('message'):
                        job.add_log(payload.get('message'))

                result = switch_remote_cert_mode(host, username, password, mode, expected_domain=expected_domain, progress=on_cert_progress, acme_mode=acme_mode, acme_webroot=acme_webroot, cf_api_token=cf_api_token)
                job.result = result
                note_text = f"证书切换 · ACME（{acme_mode}）" if mode == 'acme' else '证书切换 · 自签'
                save_entry(host=host, username=username, note=note_text, status='done' if result.get('validation', {}).get('ok') else 'error', error='' if result.get('validation', {}).get('ok') else result.get('validation', {}).get('message', ''), validation=result.get('validation', {}))
                job.add_log(result.get('message', '证书切换已完成'))
                job.status = 'done'
            except Exception as exc:
                msg = humanize_error_message(exc)
                note_text = f"证书切换 · ACME（{acme_mode}）" if mode == 'acme' else '证书切换 · 自签'
                snapshot = None
                try:
                    snapshot = {
                        'mode': mode,
                        'cert': build_remote_cert_status(host, username, password, expected_domain=expected_domain),
                        'validation': validate_remote_cert_switch(host, username, password, expected_domain=expected_domain),
                    }
                    job.result = {**(job.result or {}), **snapshot}
                except Exception:
                    snapshot = None
                save_entry(host=host, username=username, note=note_text, status='error', error=msg, validation=(snapshot or {}).get('validation', {}))
                job.error = msg
                if snapshot and snapshot.get('cert'):
                    cert = snapshot.get('cert') or {}
                    job.add_log(f"失败后状态回读：当前证书={cert.get('mode') or 'unknown'}，状态={cert.get('status') or 'unknown'}，说明={cert.get('message') or '-'}")
                job.add_log(msg)
                job.status = 'error'

        threading.Thread(target=worker, daemon=True).start()
        return jsonify({'ok': True, 'job_id': job.id})
    except Exception as exc:
        return jsonify({'ok': False, 'error': humanize_error_message(exc)}), 400


@app.route('/connect-test', methods=['POST'])
def connect_test():
    host = request.form.get('host', '').strip()
    username = request.form.get('username', '').strip() or 'root'
    password = request.form.get('password', '')

    if not host or not username or not password:
        return jsonify({'ok': False, 'error': '请填写服务器地址、用户名、密码后再测试连接。'}), 400

    try:
        from core.ssh_client import SSHRunner
        with SSHRunner(host, username, password, timeout=10) as runner:
            code, out, err = runner.run('echo CONNECT_OK && whoami && uname -a', timeout=20)
            if code != 0:
                return jsonify({'ok': False, 'error': err or '连接测试失败', 'kind': 'unknown'}), 400
            save_server(host=host, username=username, password=password)
            set_last_connect_test(host, username, True, '最近一次连接测试成功')
            return jsonify({'ok': True, 'message': out.strip(), 'kind': 'success'})
    except Exception as exc:
        msg = humanize_error_message(exc)
        kind = 'unknown'
        low = str(exc).lower()
        if 'authentication failed' in low:
            kind = 'auth'
        elif 'timed out' in low or 'timeout' in low:
            kind = 'timeout'
        elif 'refused' in low:
            kind = 'refused'
        elif 'name or service not known' in low or 'nodename nor servname provided' in low:
            kind = 'dns'
        summary_map = {'auth': '最近一次连接测试失败：用户名或密码错误', 'timeout': '最近一次连接测试失败：连接超时', 'refused': '最近一次连接测试失败：连接被拒绝', 'dns': '最近一次连接测试失败：服务器地址解析失败', 'unknown': '最近一次连接测试失败'}
        set_last_connect_test(host, username, False, summary_map.get(kind, '最近一次连接测试失败'))
        return jsonify({'ok': False, 'error': msg, 'kind': kind}), 500


@app.route('/availability/check', methods=['POST'])
def availability_check():
    host = request.form.get('host', '').strip()
    username = request.form.get('username', '').strip() or 'root'
    password = request.form.get('password', '')
    if not host or not username or not password:
        return jsonify({'ok': False, 'error': '请先填写服务器地址、用户名、密码。'}), 400

    targets = [
        ('YouTube', 'https://www.youtube.com'),
        ('Netflix', 'https://www.netflix.com/title/81215567'),
        ('Disney+', 'https://www.disneyplus.com'),
        ('OpenAI', 'https://chat.openai.com'),
    ]

    try:
        from core.ssh_client import SSHRunner
        checks = []
        with SSHRunner(host, username, password, timeout=12) as runner:
            geo = {}
            geo_sources = [
                "curl -sS --retry 2 --retry-delay 1 --max-time 8 https://ipinfo.io/json || true",
                "curl -sS --retry 2 --retry-delay 1 --max-time 8 https://ipapi.co/json || true",
            ]
            for geo_cmd in geo_sources:
                code_geo, out_geo, err_geo = runner.run(geo_cmd, timeout=20)
                try:
                    import json as _json
                    candidate = _json.loads((out_geo or '').strip() or '{}')
                except Exception:
                    candidate = {}
                if candidate.get('country') or candidate.get('country_code'):
                    geo = candidate
                    break
            country = (geo.get('country') or geo.get('country_code') or '').strip().upper()
            country_name_map = {
                'JP': '日本',
                'SG': '新加坡',
                'US': '美国',
                'HK': '香港',
                'KR': '韩国',
                'TW': '台湾',
                'DE': '德国',
                'GB': '英国',
                'FR': '法国',
            }
            city = (geo.get('city') or '').strip()
            region = (geo.get('region') or '').strip()
            loc_parts = [part for part in [country_name_map.get(country, ''), region, city] if part]
            detected_location = ' / '.join(loc_parts) if loc_parts else (country or '未知')
            region_hint = f'当前检测到服务器出口地区：{detected_location}。'
            for name, url in targets:
                cmd = f"curl -sS --retry 2 --retry-delay 1 -o /dev/null -w '%{{http_code}}' --max-time 8 '{url}' || true"
                code, out, err = runner.run(cmd, timeout=20)
                raw = (out or '').strip()
                status_code = raw if raw.isdigit() else '000'
                passed = status_code not in {'000', '403', '451', '503'}
                checks.append({
                    'name': name,
                    'url': url,
                    'status_code': status_code,
                    'passed': passed,
                    'detail': '可达' if passed else ('疑似受限或不可达' if status_code != '000' else '连接失败/超时'),
                })
        passed_count = sum(1 for item in checks if item.get('passed'))
        country_code = country or '未知'
        country_name = country_name_map.get(country, '') if country else ''
        summary = {
            'passed': passed_count,
            'total': len(checks),
            'country': country_code,
            'country_name': country_name,
            'detected_location': detected_location,
            'region_hint': region_hint,
            'note': '仅检测服务器当前实际出口地区与连通性；不基于节点名称国家做判断。',
        }
        set_last_availability(host, username, summary)
        return jsonify({'ok': True, 'checks': checks, 'summary': summary})
    except Exception as exc:
        return jsonify({'ok': False, 'error': humanize_error_message(exc)}), 400


@app.route('/deploy', methods=['POST'])
def deploy():
    host = request.form.get('host', '').strip()
    username = request.form.get('username', '').strip() or 'root'
    password = request.form.get('password', '')
    note = request.form.get('note', '').strip()

    if not host or not username or not password:
        return jsonify({'ok': False, 'error': '请把服务器地址、用户名、密码填完整。'}), 400

    job = create_job()

    save_server(host=host, username=username, note=note, password=password)

    def worker():
        job.status = 'running'
        try:
            result = deploy_to_server(host=host, username=username, password=password, log=job.add_log, settings=load_settings())
            job.result = result
            job.status = 'done'
            save_entry(host=host, username=username, note=note, status='done', nodes=result.get('nodes', []), ports=summarize_ports(result.get('nodes', [])), validation=result.get('validation', {}))
            invalidate_subscription_snapshot(host, username)
            set_server_status(host, username, True)
        except Exception as exc:
            job.error = humanize_error_message(exc)
            job.add_log(f'执行失败：{job.error}')
            job.status = 'error'
            save_entry(host=host, username=username, note=note, status='error', error=job.error)

    threading.Thread(target=worker, daemon=True).start()
    return jsonify({'ok': True, 'job_id': job.id})


@app.route('/status/<job_id>', methods=['GET'])
def status(job_id):
    job = get_job(job_id)
    if not job:
        return jsonify({'ok': False, 'error': '任务不存在'}), 404

    return jsonify(
        {
            'ok': True,
            'job': {
                'id': job.id,
                'status': job.status,
                'logs': '\n\n'.join(job.logs),
                'result': job.result,
                'error': job.error,
            },
        }
    )


@app.route('/history', methods=['GET'])
def history():
    return jsonify({'ok': True, 'items': load_history()})






@app.route('/history/delete', methods=['POST'])
def history_delete():
    entry_id = request.form.get('id', '').strip()
    if not entry_id:
        return jsonify({'ok': False, 'error': '缺少记录 id'}), 400
    delete_history_entry(entry_id)
    return jsonify({'ok': True})


@app.route('/history/<entry_id>', methods=['GET'])
def history_detail(entry_id):
    item = get_history_entry(entry_id)
    if not item:
        return jsonify({'ok': False, 'error': '记录不存在'}), 404
    return jsonify({'ok': True, 'item': item})




@app.route('/servers/latest-warning', methods=['GET'])
def servers_latest_warning():
    host = request.args.get('host', '').strip()
    if not host:
        return jsonify({'ok': False, 'error': '缺少 host'}), 400
    item = get_latest_warning_history_by_host(host)
    return jsonify({'ok': True, 'item': item})


@app.route('/servers/refresh', methods=['POST'])
def servers_refresh():
    from core.ssh_client import SSHRunner
    items = load_servers()
    refreshed = []
    for item in items:
        host = item.get('host', '')
        username = item.get('username', '') or 'root'
        password = item.get('password', '') or request.form.get('password', '')
        status = 'error'
        try:
            with SSHRunner(host, username, password) as runner:
                code, out, err = runner.run('systemctl is-active yingnode-sing-box.service || true', timeout=30)
                value = (out or '').strip()
                status = 'deployed' if value == 'active' else 'idle'
        except Exception:
            status = 'error'
        update_server_runtime_status(host, username, status)
        refreshed.append({'host': host, 'username': username, 'status': status})
    return jsonify({'ok': True, 'items': refreshed})


@app.route('/servers', methods=['GET'])
def servers():
    items = load_servers()
    enriched = []
    settings = load_settings()
    default_sni = settings.get('default_sni', '')
    for item in items:
        current = dict(item)
        current['validation'] = get_latest_validation_by_host(item.get('host', ''))
        current['validation_summary'] = summarize_validation_issue(current['validation'])
        warning_item = get_latest_warning_history_by_host(item.get('host', ''))
        current['warning_history_id'] = warning_item.get('id') if warning_item else ''
        cert_item = get_latest_cert_history_by_host(item.get('host', ''))
        current['cert_history_id'] = cert_item.get('id') if cert_item else ''
        current['cert_history_status'] = cert_item.get('status') if cert_item else ''
        current['cert_history_note'] = cert_item.get('note') if cert_item else ''
        current['cert_history_error'] = cert_item.get('error') if cert_item else ''
        current['cert_history_recent'] = get_recent_cert_history_by_host(item.get('host', ''), limit=3)
        current['cert'] = None
        try:
            deployed = current.get('status') == 'deployed' or current.get('deployed')
            if deployed and current.get('host') and current.get('password'):
                current['cert'] = get_cached_cert_status(current.get('host', ''), current.get('username', '') or 'root', current.get('password', ''), expected_domain=default_sni)
        except Exception:
            current['cert'] = None
        enriched.append(current)
    if request.args.get('mock_cert_risk', '').strip() in {'1', 'true', 'yes'}:
        enriched = apply_mock_cert_risk(enriched)
    return jsonify({'ok': True, 'items': enriched})


@app.route('/servers/delete', methods=['POST'])
def servers_delete():
    host = request.form.get('host', '').strip()
    username = request.form.get('username', '').strip()
    if not host or not username:
        return jsonify({'ok': False, 'error': '缺少 host 或 username'}), 400
    delete_server(host, username)
    return jsonify({'ok': True})


# ==================== 免费节点 API ====================
from core.free_nodes_fetcher import (
    fetch_free_nodes,
    start_free_nodes_scheduler,
)
from core import free_nodes_fetcher

_free_nodes_fetch_lock = threading.Lock()
_free_nodes_fetching = False


def _bg_fetch_free_nodes():
    """后台线程抓取免费节点"""
    global _free_nodes_fetching
    if _free_nodes_fetching:
        return
    with _free_nodes_fetch_lock:
        _free_nodes_fetching = True
        try:
            fetch_free_nodes()
        finally:
            _free_nodes_fetching = False


@app.route('/api/free/today', methods=['GET'])
def get_today_free_nodes():
    cache = free_nodes_fetcher.FREE_NODES_CACHE
    cache_expired = (
        cache is None
        or (time.time() - free_nodes_fetcher.LAST_FETCH_TIME > free_nodes_fetcher.CACHE_DURATION)
    )

    if cache_expired and not _free_nodes_fetching:
        # 在后台线程中抓取，不阻塞 HTTP 请求
        threading.Thread(target=_bg_fetch_free_nodes, daemon=True).start()

    if cache is not None:
        return jsonify(cache)

    # 首次启动，缓存还没准备好
    return jsonify({
        "status": "loading",
        "message": "节点正在抓取中，请稍后再试（约1-2分钟）...",
        "nodes_count": 0,
        "subscription": "",
    })


@app.route('/api/free/subscribe', methods=['GET'])
def get_free_subscription():
    """标准订阅链接 —— 直接返回 base64 文本，可添加到任何 VPN 客户端"""
    from flask import Response
    cache = free_nodes_fetcher.FREE_NODES_CACHE

    cache_expired = (
        cache is None
        or (time.time() - free_nodes_fetcher.LAST_FETCH_TIME > free_nodes_fetcher.CACHE_DURATION)
    )
    if cache_expired and not _free_nodes_fetching:
        threading.Thread(target=_bg_fetch_free_nodes, daemon=True).start()

    if cache is None or not cache.get('subscription'):
        return Response("", content_type='text/plain; charset=utf-8', status=503)

    return Response(
        cache['subscription'],
        content_type='text/plain; charset=utf-8',
        headers={
            'Content-Disposition': 'attachment; filename="free_nodes.txt"',
            'Subscription-Userinfo': f'upload=0; download=0; total=10737418240; expire={int(time.time()) + 86400}',
            'Profile-Update-Interval': '6',
        }
    )


if __name__ == '__main__':
    start_free_nodes_scheduler()
    # 启动时立即在后台开始抓取
    threading.Thread(target=_bg_fetch_free_nodes, daemon=True).start()
    app.run(debug=True, host='127.0.0.1', port=5001)

