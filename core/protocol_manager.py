"""High-level protocol installation / removal / patch orchestrator.

This module is the coordinator that ties together:

- ``core.ssh_client`` (connect to the VPS)
- ``core.singbox_config`` (parse / modify / serialize config.json)
- ``core.protocols`` (build inbound dicts from user params)
- ``core.models.ProtocolInstance`` (persist which protocols are live)

Every incremental operation follows the same pattern:

    1. SSH pull /etc/s-box/config.json
    2. Python mutation (pure function)
    3. SSH push the updated file
    4. systemctl reload sing-box
    5. Update DB

If any step fails after the remote file has been replaced, the DB is still
updated to reflect reality (the on-disk config) — callers can retry the
reload out of band.
"""
from __future__ import annotations

import os
import re
import tempfile
from typing import Any, Dict, List, Optional, Tuple

from core.db import get_session
from core.models import ProtocolInstance, Server
from core.protocols import get as get_protocol_spec
from core.protocols.registry import protocol_names
from core.singbox_config import (
    add_inbound,
    find_inbound,
    parse_config,
    remove_inbound,
    serialize_config,
    update_inbound,
)
from core.ssh_client import SSHRunner


REMOTE_CONFIG_PATH = "/etc/s-box/config.json"
REMOTE_SINGBOX_BINARY = "/etc/s-box/sing-box"
SYSTEMD_SERVICE_NAME = "yingnode-sing-box"


class ProtocolManagerError(Exception):
    """Any failure during an incremental protocol operation."""


# ---- Server lookup --------------------------------------------------


def _get_server(server_id: int) -> Server:
    with get_session() as session:
        srv = session.query(Server).filter_by(id=server_id).one_or_none()
        if not srv:
            raise ProtocolManagerError(f"no server with id={server_id}")
        session.expunge(srv)
        return srv


def _open_ssh(server: Server) -> SSHRunner:
    """Open an SSHRunner bound to this server. Caller uses it as a
    context manager (``with _open_ssh(srv) as ssh:``) to ensure cleanup.
    """
    return SSHRunner(
        host=server.host,
        username=server.username,
        password=server.plain_password,
        port=22,
    )


# ---- Remote config I/O ----------------------------------------------


def _fetch_remote_config(ssh: SSHRunner) -> Dict[str, Any]:
    code, out, err = ssh.run(f"cat {REMOTE_CONFIG_PATH}")
    if code != 0 or not out.strip():
        raise ProtocolManagerError(
            f"failed to read {REMOTE_CONFIG_PATH}: exit={code} err={err.strip()[:200]}"
        )
    try:
        return parse_config(out)
    except ValueError as exc:
        raise ProtocolManagerError(f"remote config is not valid JSON: {exc}")


def _push_remote_config(ssh: SSHRunner, config: Dict[str, Any]) -> None:
    """Write ``config`` back to ``REMOTE_CONFIG_PATH`` atomically (write to
    a temp file, then ``mv`` into place so a partial write never leaves
    sing-box with a broken config)."""
    text = serialize_config(config)
    temp_path: Optional[str] = None
    try:
        fd, temp_path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)

        remote_staging = f"{REMOTE_CONFIG_PATH}.new"
        ssh.upload(temp_path, remote_staging)
        code, _, err = ssh.run(f"mv {remote_staging} {REMOTE_CONFIG_PATH}")
        if code != 0:
            raise ProtocolManagerError(
                f"failed to replace config atomically: {err.strip()[:200]}"
            )
    finally:
        if temp_path and os.path.exists(temp_path):
            os.unlink(temp_path)


def _validate_remote_config(ssh: SSHRunner) -> None:
    """Ask sing-box to validate the on-disk config. Raises on error."""
    code, out, err = ssh.run(
        f"{REMOTE_SINGBOX_BINARY} check -c {REMOTE_CONFIG_PATH}"
    )
    if code != 0:
        raise ProtocolManagerError(
            f"sing-box config check failed: {(err or out).strip()[:400]}"
        )


def _reload_singbox(ssh: SSHRunner) -> None:
    """Restart sing-box (sing-box doesn't reliably support reload)."""
    code, out, err = ssh.run(f"systemctl restart {SYSTEMD_SERVICE_NAME}")
    if code != 0:
        raise ProtocolManagerError(
            f"systemctl restart failed: {(err or out).strip()[:200]}"
        )


# ---- Parameter generation (requires SSH) ----------------------------


def _generate_uuid_remote(ssh: SSHRunner) -> str:
    code, out, _ = ssh.run(f"{REMOTE_SINGBOX_BINARY} generate uuid")
    if code != 0 or not out.strip():
        raise ProtocolManagerError("sing-box generate uuid failed")
    return out.strip()


def _generate_reality_keypair_remote(ssh: SSHRunner) -> Tuple[str, str]:
    code, out, _ = ssh.run(f"{REMOTE_SINGBOX_BINARY} generate reality-keypair")
    if code != 0:
        raise ProtocolManagerError("sing-box generate reality-keypair failed")
    priv = pub = ""
    for line in out.splitlines():
        m = re.match(r"\s*PrivateKey:\s*([A-Za-z0-9_\-+/=]+)", line)
        if m:
            priv = m.group(1)
        m = re.match(r"\s*PublicKey:\s*([A-Za-z0-9_\-+/=]+)", line)
        if m:
            pub = m.group(1)
    if not priv or not pub:
        raise ProtocolManagerError(f"could not parse reality-keypair output: {out!r}")
    return priv, pub


def _fill_generated_params(
    proto_name: str,
    params: Dict[str, Any],
    ssh: SSHRunner,
) -> Dict[str, Any]:
    """Populate per-protocol params that must come from the VPS (or can be
    generated locally). Returns a NEW dict — doesn't mutate the input.

    Protocols whose missing fields are satisfied here:

    - vless_reality : uuid (remote), reality keypair (remote), short_id (local)
    - vmess_ws      : uuid (remote), path default
    - hysteria2     : password (remote uuid — matches install.sh parity)
    - tuic          : uuid (remote), password (= uuid, matches install.sh)
    - trojan        : password (remote uuid)
    - shadowsocks_2022 : method + password (local, cryptographically random)
    - anytls        : password (remote uuid)

    Certificate paths (``cert_path`` / ``key_path``) are intentionally NOT
    generated here — they refer to files written by the full ``install.sh``
    during initial VPS prep. If a protocol needs them and they're missing,
    the build step will fall back to the default ``/etc/s-box/cert.pem``.
    """
    import secrets

    out = dict(params)
    cached_uuid: Optional[str] = None

    def _uuid() -> str:
        nonlocal cached_uuid
        if cached_uuid is None:
            cached_uuid = _generate_uuid_remote(ssh)
        return cached_uuid

    if proto_name == "vless_reality":
        if not out.get("uuid"):
            out["uuid"] = _uuid()
        if not out.get("private_key"):
            priv, pub = _generate_reality_keypair_remote(ssh)
            out["private_key"] = priv
            out["_reality_public_key"] = pub
        out.setdefault("sni", "apple.com")
        if not out.get("short_id"):
            out["short_id"] = secrets.token_hex(4)

    elif proto_name == "vmess_ws":
        if not out.get("uuid"):
            out["uuid"] = _uuid()
        out.setdefault("host", "www.bing.com")
        if not out.get("path"):
            out["path"] = f"/{out['uuid']}-vm"

    elif proto_name == "hysteria2":
        if not out.get("password"):
            out["password"] = _uuid()

    elif proto_name == "tuic":
        if not out.get("uuid"):
            out["uuid"] = _uuid()
        if not out.get("password"):
            out["password"] = out["uuid"]
        out.setdefault("congestion_control", "bbr")

    elif proto_name == "trojan":
        if not out.get("password"):
            out["password"] = _uuid()
        out.setdefault("name", "yingnode")
        out.setdefault("sni", "apple.com")

    elif proto_name == "shadowsocks_2022":
        from core.protocols.shadowsocks_2022 import (
            DEFAULT_METHOD,
            generate_shadowsocks_password,
        )
        out.setdefault("method", DEFAULT_METHOD)
        if not out.get("password"):
            out["password"] = generate_shadowsocks_password(out["method"])

    elif proto_name == "anytls":
        if not out.get("password"):
            out["password"] = _uuid()
        out.setdefault("name", "yingnode")
        out.setdefault("sni", "apple.com")

    return out


def _pick_port_remote(ssh: SSHRunner, preferred: Optional[int] = None) -> int:
    """Return ``preferred`` if it's free, otherwise shuf a free port in
    20000-45000. Parallels ``random_port`` in install.sh."""
    def _in_use(port: int) -> bool:
        code, out, _ = ssh.run(f"ss -lntup 2>/dev/null | grep -q ':{port} '")
        return code == 0

    if preferred and not _in_use(preferred):
        return preferred

    for _ in range(60):
        code, out, _ = ssh.run("shuf -i 20000-45000 -n 1")
        if code == 0 and out.strip().isdigit():
            candidate = int(out.strip())
            if not _in_use(candidate):
                return candidate

    raise ProtocolManagerError("could not find a free port in 20000-45000")


# ---- Public API -----------------------------------------------------


def list_protocols(server_id: int) -> List[Dict[str, Any]]:
    with get_session() as session:
        rows = (
            session.query(ProtocolInstance)
            .filter_by(server_id=server_id)
            .order_by(ProtocolInstance.id)
            .all()
        )
        return [r.to_dict() for r in rows]


def install_protocol(
    server_id: int,
    proto_name: str,
    params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Install a protocol instance on the target VPS.

    If ``params`` omits required fields (e.g. UUID, private_key for VLESS
    Reality), they are generated server-side by running ``sing-box generate``
    over SSH. This matches the behavior of the legacy ``install.sh``.
    """
    if proto_name not in protocol_names():
        raise ProtocolManagerError(
            f"unknown protocol {proto_name!r}. Supported: {protocol_names()}"
        )

    spec = get_protocol_spec(proto_name)
    params = dict(params or {})

    server = _get_server(server_id)

    with _open_ssh(server) as ssh:
        # 1. Fill in any missing generated fields.
        params.setdefault("port", None)
        if not params.get("port"):
            params["port"] = _pick_port_remote(ssh)

        params = _fill_generated_params(proto_name, params, ssh)

        # 2. Build the inbound.
        inbound = spec.build_inbound({k: v for k, v in params.items() if not k.startswith("_")})
        tag = inbound["tag"]

        # 3. Fetch remote config, add inbound, validate, push, reload.
        remote_cfg = _fetch_remote_config(ssh)

        if find_inbound(remote_cfg, tag):
            # Tag collision — replace in place for idempotency.
            new_cfg = update_inbound(remote_cfg, tag, inbound)
        else:
            new_cfg = add_inbound(remote_cfg, inbound)

        _push_remote_config(ssh, new_cfg)

        try:
            _validate_remote_config(ssh)
            _reload_singbox(ssh)
        except ProtocolManagerError:
            # Roll back: push the original config and re-raise.
            try:
                _push_remote_config(ssh, remote_cfg)
                _reload_singbox(ssh)
            except Exception:
                pass
            raise

    # 4. Persist to DB (strip internal fields before storing).
    persisted_params = {k: v for k, v in params.items() if not k.startswith("_")}
    with get_session() as session:
        existing = (
            session.query(ProtocolInstance)
            .filter_by(server_id=server_id, tag=tag)
            .one_or_none()
        )
        if existing:
            existing.proto = proto_name
            existing.port = int(params["port"])
            existing.params = persisted_params
            existing.status = "running"
            existing.last_error = None
            inst_id = existing.id
        else:
            new_row = ProtocolInstance(
                server_id=server_id,
                proto=proto_name,
                tag=tag,
                port=int(params["port"]),
                params=persisted_params,
                status="running",
            )
            session.add(new_row)
            session.flush()
            inst_id = new_row.id
        session.commit()

    return {
        "ok": True,
        "instance_id": inst_id,
        "proto": proto_name,
        "tag": tag,
        "port": int(params["port"]),
        "params": persisted_params,
        # Expose generated public key to the caller so the client can show
        # it to the user for building Reality share links.
        "generated": {
            "reality_public_key": params.get("_reality_public_key"),
        },
    }


def uninstall_protocol(server_id: int, tag: str) -> Dict[str, Any]:
    """Remove one protocol instance from the VPS. Idempotent: if the
    inbound is already absent from the remote config, the DB row (if any)
    is still cleaned up."""
    server = _get_server(server_id)

    with _open_ssh(server) as ssh:
        remote_cfg = _fetch_remote_config(ssh)
        if find_inbound(remote_cfg, tag):
            new_cfg = remove_inbound(remote_cfg, tag)
            _push_remote_config(ssh, new_cfg)
            _validate_remote_config(ssh)
            _reload_singbox(ssh)

    deleted = 0
    with get_session() as session:
        deleted = (
            session.query(ProtocolInstance)
            .filter_by(server_id=server_id, tag=tag)
            .delete()
        )
        session.commit()

    return {"ok": True, "tag": tag, "deleted": deleted}


def reconcile(server_id: int) -> Dict[str, Any]:
    """Compare the VPS's on-disk config with the DB's ProtocolInstance
    rows. Returns a diff report; does NOT modify anything."""
    server = _get_server(server_id)

    with _open_ssh(server) as ssh:
        remote_cfg = _fetch_remote_config(ssh)
        remote_inbounds = remote_cfg.get("inbounds") or []
        remote_tags = {ib.get("tag") for ib in remote_inbounds if ib.get("tag")}

    with get_session() as session:
        db_rows = session.query(ProtocolInstance).filter_by(server_id=server_id).all()
        db_tags = {r.tag for r in db_rows}

    only_remote = sorted(remote_tags - db_tags)
    only_db = sorted(db_tags - remote_tags)
    matching = sorted(remote_tags & db_tags)

    return {
        "ok": True,
        "server_id": server_id,
        "in_sync": not only_remote and not only_db,
        "only_on_vps": only_remote,      # inbounds the VPS has that DB doesn't
        "only_in_db": only_db,            # DB rows whose inbound is missing on VPS
        "matching": matching,
    }
