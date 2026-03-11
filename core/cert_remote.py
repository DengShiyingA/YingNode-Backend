import json
import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from core.ssh_client import SSHRunner

REMOTE_CONFIG = '/etc/s-box/config.json'


def _read_remote(runner: SSHRunner, path: str) -> str:
    code, out, err = runner.run(f"test -f {path} && cat {path} || true")
    return out.strip() if code == 0 else ''


def _path_parent(path: str) -> str:
    return '/'.join((path or '').split('/')[:-1]) or '/tmp'


def read_remote_config_json(runner: SSHRunner):
    text = _read_remote(runner, REMOTE_CONFIG)
    if not text:
        return None
    try:
        return json.loads(text)
    except Exception:
        return None


def find_remote_cert_paths(config: dict):
    if not config:
        return {}
    for inbound in config.get('inbounds', []):
        tls = inbound.get('tls') or {}
        cert_path = tls.get('certificate_path') or tls.get('cert_path')
        key_path = tls.get('key_path') or tls.get('private_key_path')
        if cert_path or key_path:
            return {
                'cert_path': cert_path or '',
                'key_path': key_path or '',
                'server_name': tls.get('server_name') or '',
                'inbound_tag': inbound.get('tag') or '',
            }
    return {}


def remote_file_exists(runner: SSHRunner, path: str) -> bool:
    if not path:
        return False
    code, out, err = runner.run(f"test -f {path} && echo yes || true")
    return (out or '').strip() == 'yes'


def read_remote_cert_openssl_meta(runner: SSHRunner, cert_path: str):
    if not cert_path:
        return {}

    code, out, err = runner.run(
        f"openssl x509 -in '{cert_path}' -noout -dates -subject -issuer 2>/dev/null || true"
    )
    base_text = (out or '').strip()
    if not base_text:
        return {}

    meta = {'raw': base_text, 'san': []}
    for line in base_text.splitlines():
        line = line.strip()
        if line.startswith('notBefore='):
            meta['not_before'] = line.split('=', 1)[1].strip()
        elif line.startswith('notAfter='):
            meta['not_after'] = line.split('=', 1)[1].strip()
        elif line.startswith('subject='):
            meta['subject'] = line.split('=', 1)[1].strip()
        elif line.startswith('issuer='):
            meta['issuer'] = line.split('=', 1)[1].strip()

    code, out, err = runner.run(
        f"openssl x509 -in '{cert_path}' -noout -ext subjectAltName 2>/dev/null || true"
    )
    san_text = (out or '').strip()
    if san_text:
        for line in san_text.splitlines():
            line = line.strip()
            if 'DNS:' in line:
                meta['san'].extend(re.findall(r'DNS:([^,\s]+)', line))

    meta['san'] = list(dict.fromkeys(meta.get('san', [])))
    return meta


def detect_cert_mode(meta: dict):
    issuer = (meta.get('issuer') or '').lower()
    subject = (meta.get('subject') or '').lower()
    if not issuer and not subject:
        return 'none'
    if issuer and subject and issuer == subject:
        return 'selfsigned'
    acme_signals = ['let\'s encrypt', 'zerossl', 'google trust', 'buypass']
    if any(signal in issuer for signal in acme_signals):
        return 'acme'
    return 'unknown'


def _parse_openssl_time(value: str):
    if not value:
        return None
    try:
        dt = parsedate_to_datetime(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def calc_cert_days_left(not_after: str):
    dt = _parse_openssl_time(not_after)
    if not dt:
        return {'expires_at': '', 'days_left': None}
    now = datetime.now(timezone.utc)
    delta = dt - now
    return {
        'expires_at': dt.astimezone().strftime('%Y-%m-%d %H:%M:%S'),
        'days_left': delta.days,
    }


def check_cert_domain_match(expected_domain: str, san_list, subject: str):
    expected = (expected_domain or '').strip().lower()
    if not expected:
        return True
    sans = [str(x).strip().lower() for x in (san_list or []) if str(x).strip()]
    if expected in sans:
        return True
    m = re.search(r'CN\s*=\s*([^,\/]+)', subject or '', flags=re.I)
    if m and m.group(1).strip().lower() == expected:
        return True
    return False


def _guess_zone_candidates(domain: str):
    value = (domain or '').strip().lower().strip('.')
    if not value:
        return []
    parts = [x for x in value.split('.') if x]
    if len(parts) <= 2:
        return [value]
    candidates = [value, '.'.join(parts[-2:])]
    if len(parts) >= 3:
        candidates.append('.'.join(parts[-3:]))
    ordered = []
    for item in candidates:
        if item and item not in ordered:
            ordered.append(item)
    return ordered


def build_remote_cert_status(host: str, username: str, password: str, expected_domain: str = ''):
    with SSHRunner(host, username, password) as runner:
        config = read_remote_config_json(runner)
        found = find_remote_cert_paths(config or {})
        cert_path = found.get('cert_path', '')
        key_path = found.get('key_path', '')
        remote_server_name = found.get('server_name', '') or ''
        server_name = remote_server_name or expected_domain or ''
        domain_source = 'remote_server_name' if remote_server_name else ('default_sni' if expected_domain else 'unknown')
        if not cert_path and not key_path:
            return {
                'mode': 'none',
                'status': 'missing',
                'domain': server_name,
                'issued_at': '',
                'expires_at': '',
                'days_left': None,
                'cert_path': cert_path,
                'key_path': key_path,
                'server_name': server_name,
                'domain_source': domain_source,
                'issuer': '',
                'subject': '',
                'san': [],
                'message': '当前配置未检测到证书路径',
            }
        if not remote_file_exists(runner, cert_path) or not remote_file_exists(runner, key_path):
            return {
                'mode': 'none',
                'status': 'missing',
                'domain': server_name,
                'issued_at': '',
                'expires_at': '',
                'days_left': None,
                'cert_path': cert_path,
                'key_path': key_path,
                'server_name': server_name,
                'domain_source': domain_source,
                'issuer': '',
                'subject': '',
                'san': [],
                'message': '未检测到证书文件或私钥文件',
            }
        meta = read_remote_cert_openssl_meta(runner, cert_path)
        if not meta:
            return {
                'mode': 'unknown',
                'status': 'error',
                'domain': server_name,
                'issued_at': '',
                'expires_at': '',
                'days_left': None,
                'cert_path': cert_path,
                'key_path': key_path,
                'server_name': server_name,
                'domain_source': domain_source,
                'issuer': '',
                'subject': '',
                'san': [],
                'message': '证书读取失败，请检查 openssl 或证书文件内容',
            }
        mode = detect_cert_mode(meta)
        issued_dt = _parse_openssl_time(meta.get('not_before', ''))
        issued_at = issued_dt.astimezone().strftime('%Y-%m-%d %H:%M:%S') if issued_dt else ''
        calc = calc_cert_days_left(meta.get('not_after', ''))
        days_left = calc.get('days_left')
        status = 'ok'
        message = '当前证书有效'
        if days_left is None:
            status = 'error'
            message = '无法解析证书到期时间'
        elif days_left < 0:
            status = 'expired'
            message = '证书已过期，请尽快重签'
        elif days_left <= 30:
            status = 'expiring'
            if days_left <= 3:
                message = f'证书将在 {days_left} 天内过期，风险很高，请尽快处理'
            elif days_left <= 7:
                message = f'证书将在 {days_left} 天内过期，建议本周内处理'
            elif days_left <= 14:
                message = f'证书将在 {days_left} 天后过期，建议提前检查续期链路'
            else:
                message = f'证书将在 {days_left} 天后过期'
        if status in {'ok', 'expiring'} and not check_cert_domain_match(server_name, meta.get('san', []), meta.get('subject', '')):
            status = 'mismatch'
            message = '证书域名与当前配置不匹配'
        label = {'selfsigned': '自签证书', 'acme': 'ACME 证书', 'unknown': '未识别证书', 'none': '未配置证书'}.get(mode, '未识别证书')
        if status == 'ok':
            message = f'当前{label}有效'
        return {
            'mode': mode,
            'status': status,
            'domain': server_name,
            'issued_at': issued_at,
            'expires_at': calc.get('expires_at', ''),
            'days_left': days_left,
            'cert_path': cert_path,
            'key_path': key_path,
            'server_name': server_name,
            'domain_source': domain_source,
            'issuer': meta.get('issuer', ''),
            'subject': meta.get('subject', ''),
            'san': meta.get('san', []),
            'message': message,
        }


def check_remote_acme_ready(host: str, username: str, password: str, expected_domain: str = '', acme_mode: str = 'standalone', acme_webroot: str = '', cf_api_token: str = ''):
    with SSHRunner(host, username, password) as runner:
        config = read_remote_config_json(runner)
        found = find_remote_cert_paths(config or {})
        server_name = found.get('server_name', '') or expected_domain or ''
        checks = []
        checks.append({'key': 'domain_present', 'label': '可用域名', 'passed': bool(server_name), 'detail': server_name or '未检测到 server_name 或默认 SNI'})

        code, out, err = runner.run("command -v openssl >/dev/null 2>&1 && echo yes || true")
        checks.append({'key': 'openssl_ready', 'label': 'OpenSSL 可用', 'passed': (out or '').strip() == 'yes', 'detail': '已检测 openssl' if (out or '').strip() == 'yes' else '远端未检测到 openssl'})

        if acme_mode == 'webroot':
            code, out, err = runner.run(f"test -d '{acme_webroot}' && echo yes || true")
            checks.append({'key': 'webroot_present', 'label': 'Webroot 路径存在', 'passed': (out or '').strip() == 'yes', 'detail': acme_webroot or '未填写 webroot 路径'})
            code, out, err = runner.run(f"test -w '{acme_webroot}' && echo yes || true") if acme_webroot else (0, '', '')
            checks.append({'key': 'webroot_writable', 'label': 'Webroot 路径可写', 'passed': bool(acme_webroot) and (out or '').strip() == 'yes', 'detail': acme_webroot or '未填写 webroot 路径'})
        elif acme_mode == 'dns_cf':
            token = (cf_api_token or '').strip()
            checks.append({'key': 'cf_token_present', 'label': 'Cloudflare Token 已配置', 'passed': bool(token), 'detail': '已检测到 Cloudflare API Token' if token else '未填写 Cloudflare API Token'})
            format_ok = bool(re.match(r'^[A-Za-z0-9._\-]{20,}$', token)) if token else False
            checks.append({'key': 'cf_token_format', 'label': 'Cloudflare Token 格式初检', 'passed': format_ok, 'detail': '格式看起来正常' if format_ok else 'Token 为空或格式异常'})
            verify_ok = False
            if token:
                code, out, err = runner.run(
                    "curl -s --max-time 10 -H \"Authorization: Bearer {token}\" -H \"Content-Type: application/json\" https://api.cloudflare.com/client/v4/user/tokens/verify || true".format(token=token)
                )
                text = (out or err or '').lower()
                verify_ok = '"success":true' in text and '"status":"active"' in text
            checks.append({'key': 'cf_token_valid', 'label': 'Cloudflare Token 可用性', 'passed': verify_ok, 'detail': 'Token 校验通过' if verify_ok else 'Token 校验未通过（可能无效、过期或权限不足）'})

            zone_found = False
            zone_hit = ''
            if token and server_name:
                for zone_name in _guess_zone_candidates(server_name):
                    code, out, err = runner.run(
                        "curl -s --max-time 10 -H \"Authorization: Bearer {token}\" -H \"Content-Type: application/json\" \"https://api.cloudflare.com/client/v4/zones?name={zone}\" || true".format(token=token, zone=zone_name)
                    )
                    text = (out or err or '').lower()
                    if '"success":true' in text and '"result":[]' not in text:
                        zone_found = True
                        zone_hit = zone_name
                        break
            checks.append({'key': 'cf_zone_found', 'label': 'Cloudflare Zone 可定位', 'passed': zone_found, 'detail': zone_hit or '未在当前 Token 可访问的 Zone 中定位到目标域名'})
        else:
            code, out, err = runner.run("ss -ltn 2>/dev/null | grep ':80 ' || true")
            port80_busy = bool((out or '').strip())
            checks.append({'key': 'port80_free', 'label': '80 端口可用', 'passed': not port80_busy, 'detail': '80 端口空闲' if not port80_busy else '80 端口已被占用'})

        code, out, err = runner.run("curl -4 -s --max-time 8 ifconfig.me || true")
        public_ip = (out or '').strip()
        checks.append({'key': 'public_ip', 'label': '公网 IP 可获取', 'passed': bool(public_ip), 'detail': public_ip or '未成功获取公网 IP'})

        passed = all(item.get('passed') for item in checks)
        failed = [item['label'] for item in checks if not item.get('passed')]
        message = 'ACME 前置检查通过，可以继续接入正式申请流程。' if passed else 'ACME 前置检查未通过：' + '、'.join(failed)
        return {
            'ok': passed,
            'mode': 'acme',
            'acme_mode': acme_mode,
            'acme_webroot': acme_webroot,
            'cf_configured': bool(cf_api_token),
            'domain': server_name,
            'public_ip': public_ip,
            'checks': checks,
            'message': message,
        }


def validate_remote_cert_switch(host: str, username: str, password: str, expected_domain: str = ''):
    cert = build_remote_cert_status(host, username, password, expected_domain=expected_domain)
    with SSHRunner(host, username, password) as runner:
        code, out, err = runner.run('systemctl is-active yingnode-sing-box.service || true', timeout=20)
        service_active = (out or '').strip() == 'active'
    checks = [
        {'key': 'service_active', 'label': 'sing-box 服务运行', 'passed': service_active, 'detail': '服务 active' if service_active else '服务未处于 active'},
        {'key': 'cert_present', 'label': '证书文件存在', 'passed': bool(cert.get('cert_path')) and cert.get('status') != 'missing', 'detail': cert.get('cert_path') or '未检测到证书路径'},
        {'key': 'key_present', 'label': '私钥文件存在', 'passed': bool(cert.get('key_path')) and cert.get('status') != 'missing', 'detail': cert.get('key_path') or '未检测到私钥路径'},
        {'key': 'cert_status_ok', 'label': '证书状态正常', 'passed': cert.get('status') in {'ok', 'expiring'}, 'detail': cert.get('message') or cert.get('status') or '-'},
        {'key': 'domain_match', 'label': '证书域名匹配', 'passed': cert.get('status') != 'mismatch', 'detail': cert.get('domain') or cert.get('server_name') or '-'},
    ]
    passed = all(item.get('passed') for item in checks)
    return {
        'ok': passed,
        'checks': checks,
        'message': '证书切换后的基础验收通过。' if passed else '证书切换后的基础验收存在异常。',
    }


def _short_error(err: str, out: str = '') -> str:
    text = (err or out or '').strip()
    if not text:
        return ''
    return text[-400:]


def _friendly_acme_error(err: str, out: str = '') -> str:
    raw = ((err or '') + '\n' + (out or '')).strip()
    text = raw.lower()
    if not text:
        return ''
    retry_after = ''
    m = re.search(r'retry\s+after\s+([0-9\-: ]+utc)', raw, flags=re.I)
    if m:
        retry_after = m.group(1).strip()
    retry_suffix = f'（建议重试时间：{retry_after}）' if retry_after else ''
    if 'rejectedidentifier' in text or 'forbidden by policy' in text:
        return '当前域名被证书机构策略拒绝签发，请改用你自己可控的正式域名。'
    if 'invalid request headers' in text or 'invalid format for authorization header' in text:
        return '当前 Cloudflare Token 格式无效，或填写的并不是标准 Cloudflare API Token，请到 Cloudflare API Tokens 页面重新创建并填写。'
    if 'invalid domain' in text and 'error adding txt record to domain' in text:
        return '当前域名无法在 Cloudflare 中定位到可写 Zone，导致 _acme-challenge TXT 记录写入失败。请确认该域名确实托管在当前 Cloudflare 账户下，并且 Token 对应 Zone 有 DNS 写权限。'
    if 'invalid response from' in text and '.well-known/acme-challenge' in text:
        if '530' in text:
            return '证书机构已访问到 challenge 地址，但当前域名返回了异常状态码 530。请检查该域名是否被 CDN/代理拦截、源站是否可达，以及 `/.well-known/acme-challenge/` 是否被正确放行。'
        return '证书机构已访问到 challenge 地址，但返回内容不符合 ACME 验证要求。请检查当前域名的 Web 服务、反向代理和 `/.well-known/acme-challenge/` 路径映射是否正确。'
    if 'too many failed authorizations recently' in text or ('authorization failures' in text and '429' in text):
        return f'当前域名在最近一小时内 ACME 授权失败次数过多，证书机构已暂时限流。请先修复验证问题，并在 retry-after 指定时间后再重试；如果当前域名走 Cloudflare，建议优先改用 dns_cf 模式。{retry_suffix}'
    if 'too many certificates already issued' in text or ('new-certificates-per-exact-set-of-identifiers' in text and '429' in text):
        return f'当前这组域名的证书申请次数已触发 Let\'s Encrypt 限流（429）。这不是 80 端口或页面故障；请按 retry-after 指定时间后再试，或优先改用 dns_cf 模式。{retry_suffix}'
    if 'please update your account with an email address first' in text or 'no eab credentials found for zerossl' in text:
        return '当前远端 acme.sh 默认落到了 ZeroSSL 注册流程，已建议改为显式使用 Let\'s Encrypt。'
    return ''


def _stage_payload(key: str, label: str, status: str = 'pending', detail: str = ''):
    return {'key': key, 'label': label, 'status': status, 'detail': detail}


def _mark_stage(stages, key: str, status: str, detail: str = ''):
    for item in stages:
        if item.get('key') == key:
            item['status'] = status
            if detail:
                item['detail'] = detail
            return


def _emit_stage(progress, mode: str, current_stage: str, stages, message: str = ''):
    if callable(progress):
        progress({
            'mode': mode,
            'current_stage': current_stage,
            'stages': [dict(item) for item in stages],
            'message': message,
        })


def switch_remote_cert_mode(host: str, username: str, password: str, mode: str, expected_domain: str = '', progress=None, acme_mode: str = 'standalone', acme_webroot: str = '', cf_api_token: str = ''):
    stages = [
        _stage_payload('prepare', '准备证书路径'),
        _stage_payload('issue' if mode == 'acme' else 'generate', '申请证书' if mode == 'acme' else '生成自签证书'),
        _stage_payload('install', '安装证书到当前路径'),
        _stage_payload('restart', '重启 sing-box 服务'),
        _stage_payload('validate', '切换后基础验收'),
    ]
    current_stage = 'prepare'
    _emit_stage(progress, mode, current_stage, stages, '开始准备证书路径')
    with SSHRunner(host, username, password) as runner:
        config = read_remote_config_json(runner)
        found = find_remote_cert_paths(config or {})
        cert_path = found.get('cert_path', '')
        key_path = found.get('key_path', '')
        server_name = found.get('server_name', '') or expected_domain or ''
        if not cert_path or not key_path:
            raise RuntimeError('当前配置未检测到证书路径，暂时无法切换证书模式。')
        if not server_name:
            raise RuntimeError('未检测到可用于生成证书的域名，请先确认当前 SNI 或 server_name。')

        cert_dir = _path_parent(cert_path)
        key_dir = _path_parent(key_path)
        _mark_stage(stages, 'prepare', 'done', '已确认当前证书与私钥路径')
        _emit_stage(progress, mode, current_stage, stages, '已确认当前证书与私钥路径')

        if mode == 'selfsigned':
            current_stage = 'generate'
            _emit_stage(progress, mode, current_stage, stages, '开始生成自签证书')
            temp_cert = cert_path + '.tmp'
            temp_key = key_path + '.tmp'
            temp_pub = cert_path + '.pub.tmp'
            subj = f'/CN={server_name}'
            cmd = (
                f"mkdir -p '{cert_dir}' '{key_dir}' && "
                f"openssl ecparam -name prime256v1 -genkey -noout -out '{temp_key}' >/dev/null 2>&1 && "
                f"openssl req -new -x509 -key '{temp_key}' -out '{temp_cert}' -days 365 -subj '{subj}' >/dev/null 2>&1 && "
                f"openssl pkey -in '{temp_key}' -pubout -out '{temp_pub}' >/dev/null 2>&1 && "
                f"openssl x509 -in '{temp_cert}' -pubkey -noout | diff -q - '{temp_pub}' >/dev/null 2>&1 && "
                f"mv '{temp_cert}' '{cert_path}' && mv '{temp_key}' '{key_path}' && rm -f '{temp_pub}' && "
                f"chmod 600 '{key_path}' && chmod 644 '{cert_path}'"
            )
            code, out, err = runner.run(cmd, timeout=60)
            if code != 0:
                _mark_stage(stages, 'generate', 'error', _short_error(err, out))
                raise RuntimeError('远端生成自签证书失败，请检查 openssl 是否可用。' + (f'\n\n详情：{_short_error(err, out)}' if _short_error(err, out) else ''))
            _mark_stage(stages, 'generate', 'done', 'ECC 自签证书已生成并写入临时目标路径')
            _mark_stage(stages, 'install', 'done', 'ECC 自签证书已替换当前主证书路径')
            _emit_stage(progress, mode, current_stage, stages, 'ECC 自签证书已生成并替换当前主证书路径')
        elif mode == 'acme':
            current_stage = 'issue'
            _emit_stage(progress, mode, current_stage, stages, '开始申请 ACME 证书')
            home = '/root/.acme.sh'
            install_cmd = "command -v curl >/dev/null 2>&1 || true"
            runner.run(install_cmd, timeout=10)
            code, out, err = runner.run(f"test -x {home}/acme.sh && echo yes || true", timeout=10)
            if (out or '').strip() != 'yes':
                code, out, err = runner.run("curl -s https://get.acme.sh | sh >/dev/null 2>&1", timeout=120)
                if code != 0:
                    _mark_stage(stages, 'issue', 'error', _short_error(err, out))
                    raise RuntimeError('远端安装 acme.sh 失败，请检查网络环境。' + (f'\n\n详情：{_short_error(err, out)}' if _short_error(err, out) else ''))
            if acme_mode == 'webroot':
                issue_cmd = (
                    f"mkdir -p '{cert_dir}' '{key_dir}' '{acme_webroot}' && "
                    f"{home}/acme.sh --issue -d '{server_name}' --webroot '{acme_webroot}' --server letsencrypt --keylength ec-256 --force"
                )
            elif acme_mode == 'dns_cf':
                issue_cmd = (
                    f"export CF_Token='{cf_api_token}' && "
                    f"mkdir -p '{cert_dir}' '{key_dir}' && "
                    f"{home}/acme.sh --issue -d '{server_name}' --dns dns_cf --server letsencrypt --keylength ec-256 --force"
                )
            else:
                issue_cmd = (
                    f"mkdir -p '{cert_dir}' '{key_dir}' && "
                    f"{home}/acme.sh --issue -d '{server_name}' --standalone --server letsencrypt --keylength ec-256 --force"
                )
            code, out, err = runner.run(issue_cmd, timeout=240)
            if code != 0:
                detail = _friendly_acme_error(err, out) or _short_error(err, out)
                _mark_stage(stages, 'issue', 'error', detail)
                raise RuntimeError('ACME 证书申请失败，请检查域名解析、80 端口和网络环境。' + (f'\n\n详情：{detail}' if detail else ''))
            _mark_stage(stages, 'issue', 'done', 'ACME 证书申请成功')
            _emit_stage(progress, mode, current_stage, stages, 'ACME 证书申请成功')
            current_stage = 'install'
            _emit_stage(progress, mode, current_stage, stages, '开始安装 ACME 证书到当前路径')
            install_cert_cmd = (
                f"{home}/acme.sh --install-cert -d '{server_name}' "
                f"--ecc --fullchain-file '{cert_path}' --key-file '{key_path}'"
            )
            code, out, err = runner.run(install_cert_cmd, timeout=120)
            if code != 0:
                _mark_stage(stages, 'install', 'error', _short_error(err, out))
                raise RuntimeError('ACME 证书已申请，但安装到当前证书路径失败。' + (f'\n\n详情：{_short_error(err, out)}' if _short_error(err, out) else ''))
            runner.run(f"chmod 600 '{key_path}' && chmod 644 '{cert_path}'", timeout=20)
            _mark_stage(stages, 'install', 'done', '证书已安装到当前主证书路径')
            _emit_stage(progress, mode, current_stage, stages, '证书已安装到当前主证书路径')
        else:
            raise RuntimeError('当前证书模式无效。')

        current_stage = 'restart'
        _emit_stage(progress, mode, current_stage, stages, '开始重启 sing-box 服务')
        code, out, err = runner.run('systemctl restart yingnode-sing-box.service', timeout=40)
        if code != 0:
            _mark_stage(stages, 'restart', 'error', _short_error(err, out))
            raise RuntimeError('证书已处理，但重启 sing-box 服务失败。' + (f'\n\n详情：{_short_error(err, out)}' if _short_error(err, out) else ''))
        _mark_stage(stages, 'restart', 'done', 'sing-box 服务已重启')
        _emit_stage(progress, mode, current_stage, stages, 'sing-box 服务已重启')

    current_stage = 'validate'
    _emit_stage(progress, mode, current_stage, stages, '开始切换后基础验收')
    cert = build_remote_cert_status(host, username, password, expected_domain=expected_domain)
    validation = validate_remote_cert_switch(host, username, password, expected_domain=expected_domain)
    _mark_stage(stages, 'validate', 'done' if validation.get('ok') else 'error', validation.get('message', ''))
    _emit_stage(progress, mode, current_stage, stages, validation.get('message', ''))
    return {
        'mode': mode,
        'message': '已切换到 ACME 证书。' if mode == 'acme' else '已切换到自签证书。',
        'cert': cert,
        'validation': validation,
        'stages': stages,
        'current_stage': current_stage,
        'acme_mode': acme_mode,
        'acme_webroot': acme_webroot,
        'cf_configured': bool(cf_api_token),
    }
