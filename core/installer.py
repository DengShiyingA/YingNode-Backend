import base64
import json
from pathlib import Path
from core.ssh_client import SSHRunner
from core.parser import NODE_FILES, extract_nodes
from core.qr import make_qr


INSTALL_COMMAND = "bash /tmp/yingnode_install.sh"
REMOTE_INSTALLER = "/tmp/yingnode_install.sh"
REMOTE_UNINSTALLER = "/tmp/yingnode_uninstall.sh"


def _safe_read_remote(runner: SSHRunner, path: str) -> str:
    code, out, err = runner.run(f"test -f {path} && cat {path} || true")
    if code == 0:
        return out.strip()
    return ''


def _run_check(runner: SSHRunner, command: str, ok_when=None, timeout: int = 30) -> dict:
    code, out, err = runner.run(command, timeout=timeout)
    output = (out or err or '').strip()
    passed = ok_when(code, out, err) if ok_when else (code == 0)
    return {
        'passed': bool(passed),
        'output': output,
    }


def _run_check_with_retry(runner: SSHRunner, command: str, ok_when=None, timeout: int = 30, retries: int = 3, delay_seconds: float = 1.2) -> dict:
    last = {'passed': False, 'output': ''}
    for i in range(max(1, retries)):
        result = _run_check(runner, command, ok_when=ok_when, timeout=timeout)
        last = result
        if result.get('passed'):
            return result
        if i < retries - 1:
            try:
                runner.run(f'sleep {delay_seconds}', timeout=5)
            except Exception:
                pass
    return last


def collect_validation(runner: SSHRunner, read_results: dict) -> dict:
    checks = []

    service_check = _run_check_with_retry(
        runner,
        'systemctl is-active yingnode-sing-box.service || true',
        ok_when=lambda code, out, err: (out or '').strip() == 'active',
        retries=4,
        delay_seconds=1.5,
    )
    checks.append({'key': 'service_active', 'label': 'sing-box 服务运行', **service_check})

    config_check = _run_check(runner, 'test -s /etc/s-box/config.json')
    checks.append({'key': 'config_exists', 'label': '主配置文件存在', **config_check})

    binary_check = _run_check(runner, 'test -x /etc/s-box/sing-box')
    checks.append({'key': 'binary_exists', 'label': 'sing-box 二进制可执行', **binary_check})

    port_commands = {
        'VLESS Reality': ('vless_port_listening', 'VLESS 端口监听'),
        'VMess WS': ('vmess_port_listening', 'VMess 端口监听'),
        'Hysteria2': ('hy2_port_listening', 'HY2 端口监听'),
        'TUIC v5': ('tuic_port_listening', 'TUIC 端口监听'),
        'Trojan TLS': ('trojan_port_listening', 'Trojan 端口监听'),
        'Shadowsocks 2022': ('ss2022_port_listening', 'SS2022 端口监听'),
        'Anytls': ('anytls_port_listening', 'AnyTLS 端口监听'),
    }
    for node_name, (key, label) in port_commands.items():
        port = _extract_port(read_results.get(node_name, ''))
        if not port:
            checks.append({'key': key, 'label': label, 'passed': False, 'output': '未读取到对应端口'})
            continue
        cmd = (
            "if command -v ss >/dev/null 2>&1; then "
            f"ss -lntup 2>/dev/null | grep -E '[:.]({port})\\s'; "
            "elif command -v netstat >/dev/null 2>&1; then "
            f"netstat -lntup 2>/dev/null | grep -E '[:.]({port})\\s'; "
            "else echo '__PORT_CHECK_TOOL_MISSING__'; fi || true"
        )
        port_check = _run_check(runner, cmd, ok_when=lambda code, out, err: bool((out or '').strip()) and '__PORT_CHECK_TOOL_MISSING__' not in (out or ''))
        checks.append({'key': key, 'label': label, **port_check, 'port': port})

    file_map = {
        'VLESS Reality': ('vless_output', 'VLESS 节点文件生成'),
        'VMess WS': ('vmess_output', 'VMess 节点文件生成'),
        'Hysteria2': ('hy2_output', 'HY2 节点文件生成'),
        'TUIC v5': ('tuic_output', 'TUIC 节点文件生成'),
        'Trojan TLS': ('trojan_output', 'Trojan 节点文件生成'),
        'Shadowsocks 2022': ('ss2022_output', 'SS2022 节点文件生成'),
        'Anytls': ('anytls_output', 'AnyTLS 节点文件生成'),
        'Sing-box 配置': ('singbox_output', 'Sing-box 配置生成'),
        'Mihomo 配置': ('mihomo_output', 'Mihomo 配置生成'),
    }
    for node_name, (key, label) in file_map.items():
        content = (read_results.get(node_name, '') or '').strip()
        checks.append({'key': key, 'label': label, 'passed': bool(content), 'output': '已生成' if content else '未生成'})

    passed_count = sum(1 for item in checks if item.get('passed'))
    return {
        'ok': passed_count == len(checks),
        'passed_count': passed_count,
        'total': len(checks),
        'checks': checks,
    }


def deploy_to_server(host: str, username: str, password: str, log=None, settings=None) -> dict:
    def emit(message: str):
        if log:
            log(message)

    project_root = Path(__file__).resolve().parent.parent
    local_installer = project_root / 'scripts' / 'install.sh'

    with SSHRunner(host, username, password) as runner:
        emit(f'已连接服务器：{host}')
        emit('开始检查远程依赖…')
        dep_cmd = "command -v bash >/dev/null 2>&1 && command -v curl >/dev/null 2>&1"
        code, out, err = runner.run(dep_cmd, timeout=120)
        if err.strip():
            emit('[stderr]\n' + err.strip())
        if code != 0:
            raise RuntimeError('远程环境缺少基础命令 bash/curl。')

        emit('上传 YingNode 自定义安装器…')
        runner.upload(str(local_installer), REMOTE_INSTALLER)
        runner.chmod(REMOTE_INSTALLER, '755')

        deploy_settings = settings or {}
        env_parts = []
        if deploy_settings.get('default_sni'):
            env_parts.append(f"SNI_DOMAIN='{deploy_settings['default_sni']}'")
        if deploy_settings.get('default_singbox_version'):
            env_parts.append(f"SINGBOX_VERSION='{deploy_settings['default_singbox_version']}'")
        if deploy_settings.get('port_mode') == 'fixed':
            if deploy_settings.get('fixed_vless_port'):
                env_parts.append(f"VLESS_PORT='{deploy_settings['fixed_vless_port']}'")
            if deploy_settings.get('fixed_vmess_port'):
                env_parts.append(f"VMESS_PORT='{deploy_settings['fixed_vmess_port']}'")
            if deploy_settings.get('fixed_hy2_port'):
                env_parts.append(f"HY2_PORT='{deploy_settings['fixed_hy2_port']}'")
            if deploy_settings.get('fixed_tuic_port'):
                env_parts.append(f"TUIC_PORT='{deploy_settings['fixed_tuic_port']}'")
            if deploy_settings.get('fixed_trojan_port'):
                env_parts.append(f"TROJAN_PORT='{deploy_settings['fixed_trojan_port']}'")
            if deploy_settings.get('fixed_ss2022_port'):
                env_parts.append(f"SS2022_PORT='{deploy_settings['fixed_ss2022_port']}'")
            if deploy_settings.get('fixed_anytls_port'):
                env_parts.append(f"ANYTLS_PORT='{deploy_settings['fixed_anytls_port']}'")
        env_prefix = (' '.join(env_parts) + ' ') if env_parts else ''

        emit('开始执行 YingNode 安装器…这个过程可能持续几分钟。')
        code, out, err = runner.run(env_prefix + INSTALL_COMMAND, timeout=3600)
        if out.strip():
            emit(out.strip())
        if err.strip():
            emit('[stderr]\n' + err.strip())

        emit(f'安装命令执行结束，退出码：{code}')
        if code != 0:
            emit('安装命令返回非 0，开始回读远端服务与关键产物，确认是否已完成部署…')
            recover_service = _run_check_with_retry(
                runner,
                'systemctl is-active yingnode-sing-box.service || true',
                ok_when=lambda c, o, e: (o or '').strip() == 'active',
                retries=4,
                delay_seconds=1.5,
            )
            recover_config = _run_check(runner, 'test -s /etc/s-box/config.json')
            recover_vless = _run_check(runner, 'test -s /etc/s-box/vl_reality.txt')
            recover_vmess = _run_check(runner, 'test -s /etc/s-box/vm_ws.txt')
            recover_trojan = _run_check(runner, 'test -s /etc/s-box/trojan.txt')
            recover_ss2022 = _run_check(runner, 'test -s /etc/s-box/ss2022.txt')
            recovered = all([
                recover_service.get('passed'),
                recover_config.get('passed'),
                recover_vless.get('passed'),
                recover_vmess.get('passed'),
                recover_trojan.get('passed'),
                recover_ss2022.get('passed'),
            ])
            if recovered:
                emit('检测到远端服务已运行且关键产物齐全，判定为部署已生效（返回码异常已降级为告警）。')
            else:
                raise RuntimeError('安装脚本执行失败，请查看上方实时日志。')
        emit('开始读取节点与配置文件…')

        read_results = {}
        for name, path in NODE_FILES.items():
            content = _safe_read_remote(runner, path)
            read_results[name] = content
            if content.strip():
                emit(f'已读取：{name}')

        emit('开始执行部署后验收检查…')
        validation = collect_validation(runner, read_results)
        for item in validation.get('checks', []):
            summary = item.get('label', item.get('key', '检查项'))
            if not item.get('passed') and item.get('port') and item.get('key', '').endswith('_port_listening'):
                summary = f"{summary.split(' ', 1)[0]} 端口 {item.get('port')} 未监听"
            emit(('✅ ' if item.get('passed') else '⚠️ ') + summary)

    nodes = extract_nodes(read_results)

    qr_dir = project_root / 'static' / 'qrcodes'
    qr_dir.mkdir(parents=True, exist_ok=True)

    qr_enabled_names = {'VLESS Reality', 'VMess WS', 'Hysteria2', 'TUIC v5', 'Trojan TLS', 'Shadowsocks 2022', 'Anytls', 'Argo VMess 节点'}
    for item in nodes:
        content = item['content']
        if item.get('name') in qr_enabled_names and '://' in content:
            qr_path = make_qr(content, str(qr_dir))
            item['qr_path'] = '/' + str(Path(qr_path).relative_to(project_root)).replace('\\', '/')

    emit('部署流程结束。')
    return {
        'nodes': nodes,
        'success': bool(nodes),
        'validation': validation,
    }


def _extract_port(content: str) -> str:
    text = (content or '').strip()
    if not text:
        return ''
    if text.startswith('vmess://'):
        try:
            raw = text[len('vmess://'):].strip()
            padded = raw + '=' * (-len(raw) % 4)
            data = json.loads(base64.b64decode(padded).decode('utf-8'))
            return str(data.get('port', '')).strip()
        except Exception:
            return ''
    try:
        main = text.split('@', 1)[1]
        tail = main.split(':', 1)[1]
        port = tail.split('?', 1)[0].split('#', 1)[0]
        return port.strip()
    except Exception:
        return ''


def uninstall_from_server(host: str, username: str, password: str, log=None) -> dict:
    def emit(message: str):
        if log:
            log(message)

    project_root = Path(__file__).resolve().parent.parent
    local_uninstaller = project_root / 'scripts' / 'uninstall.sh'

    with SSHRunner(host, username, password) as runner:
        emit(f'已连接服务器：{host}')
        emit('开始读取已有端口信息…')
        vless = _safe_read_remote(runner, '/etc/s-box/vl_reality.txt')
        vmess = _safe_read_remote(runner, '/etc/s-box/vm_ws.txt')
        hy2 = _safe_read_remote(runner, '/etc/s-box/hy2.txt')
        tuic = _safe_read_remote(runner, '/etc/s-box/tuic5.txt')
        trojan = _safe_read_remote(runner, '/etc/s-box/trojan.txt')
        ss2022 = _safe_read_remote(runner, '/etc/s-box/ss2022.txt')
        anytls = _safe_read_remote(runner, '/etc/s-box/an.txt')
        vless_port = _extract_port(vless)
        vmess_port = _extract_port(vmess)
        hy2_port = _extract_port(hy2)
        tuic_port = _extract_port(tuic)
        trojan_port = _extract_port(trojan)
        ss2022_port = _extract_port(ss2022)
        anytls_port = _extract_port(anytls)

        emit('上传卸载脚本…')
        runner.upload(str(local_uninstaller), REMOTE_UNINSTALLER)
        runner.chmod(REMOTE_UNINSTALLER, '755')

        emit('开始卸载服务器上的 YingNode 节点…')
        cmd = f"bash {REMOTE_UNINSTALLER} '{vless_port}' '{vmess_port}' '{hy2_port}' '{tuic_port}' '{trojan_port}' '{ss2022_port}' '{anytls_port}'"
        code, out, err = runner.run(cmd, timeout=1800)
        if out.strip():
            emit(out.strip())
        if err.strip():
            emit('[stderr]\n' + err.strip())
        if code != 0:
            raise RuntimeError('卸载脚本执行失败，请查看日志。')

    emit('卸载流程结束。')
    return {'success': True, 'message': 'YingNode 节点已从服务器卸载并完成校验。'}


def summarize_ports(nodes: list) -> list:
    ports = []
    for item in nodes:
        name = item.get('name', '')
        content = item.get('content', '')
        port = _extract_port(content)
        if not port:
            continue
        if name in {'VLESS Reality', 'VMess WS', 'Trojan TLS', 'Anytls'}:
            ports.append(f"{port}/tcp")
        elif name in {'Hysteria2', 'TUIC v5'}:
            ports.append(f"{port}/udp")
        elif name in {'Shadowsocks 2022'}:
            ports.append(f"{port}/tcp+udp")
    return ports
