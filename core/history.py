"""Backwards-compatible history/servers persistence layer.

Historically this module read/wrote ``data/servers.json`` and
``data/deploy_history.json`` directly. Everything now goes through SQLAlchemy
(see ``core.db``, ``core.models``) but the *function signatures and return
shapes* are unchanged so ``app.py`` and every other caller keeps working.

If you need the underlying ORM objects, import from ``core.models`` directly.
Treat this file as the legacy compatibility surface.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy import desc

from core.db import get_session, init_db
from core.models import HistoryEntry, Server


_HISTORY_LIMIT = 30
_SERVERS_LIMIT = 20


# Ensure tables exist on first import so callers who use this module
# without going through app.py (scripts, migrations, tests) still work.
init_db()


# ---- history operations ---------------------------------------------


def load_history() -> List[Dict[str, Any]]:
    with get_session() as session:
        rows = (
            session.query(HistoryEntry)
            .order_by(desc(HistoryEntry.created_at), desc(HistoryEntry.id))
            .limit(_HISTORY_LIMIT)
            .all()
        )
        return [r.to_legacy_dict() for r in rows]


def save_entry(
    host: str,
    status: str,
    username: str = "",
    note: str = "",
    nodes: Optional[List[Dict[str, Any]]] = None,
    error: Optional[str] = None,
    ports: Optional[List[str]] = None,
    validation: Optional[Dict[str, Any]] = None,
):
    with get_session() as session:
        entry = HistoryEntry(
            entry_id=uuid.uuid4().hex,
            host=host,
            username=username or "",
            note=note or "",
            status=status or "",
            created_at=datetime.utcnow(),
            node_count=len(nodes or []),
            nodes=nodes or [],
            ports=ports or [],
            validation=validation or {},
            error=error or "",
        )
        session.add(entry)
        # Cap history to the most recent N rows to mimic the JSON-era behavior.
        excess_ids = (
            session.query(HistoryEntry.id)
            .order_by(desc(HistoryEntry.created_at), desc(HistoryEntry.id))
            .offset(_HISTORY_LIMIT)
            .all()
        )
        for (row_id,) in excess_ids:
            session.query(HistoryEntry).filter(HistoryEntry.id == row_id).delete()
        session.commit()


def get_history_entry(entry_id: str):
    with get_session() as session:
        row = session.query(HistoryEntry).filter_by(entry_id=entry_id).one_or_none()
        return row.to_legacy_dict() if row else None


def delete_history_entry(entry_id: str):
    with get_session() as session:
        session.query(HistoryEntry).filter_by(entry_id=entry_id).delete()
        session.commit()


def delete_history_by_host(host: str):
    with get_session() as session:
        session.query(HistoryEntry).filter_by(host=host).delete()
        session.commit()


def get_latest_ports_by_host(host: str):
    with get_session() as session:
        row = (
            session.query(HistoryEntry)
            .filter(HistoryEntry.host == host)
            .filter(HistoryEntry.ports.isnot(None))
            .order_by(desc(HistoryEntry.created_at), desc(HistoryEntry.id))
            .first()
        )
        return list(row.ports or []) if row else []


def get_latest_validation_by_host(host: str):
    with get_session() as session:
        row = (
            session.query(HistoryEntry)
            .filter(HistoryEntry.host == host)
            .filter(HistoryEntry.validation.isnot(None))
            .order_by(desc(HistoryEntry.created_at), desc(HistoryEntry.id))
            .first()
        )
        return dict(row.validation or {}) if row else {}


def get_latest_warning_history_by_host(host: str):
    with get_session() as session:
        rows = (
            session.query(HistoryEntry)
            .filter(HistoryEntry.host == host)
            .order_by(desc(HistoryEntry.created_at), desc(HistoryEntry.id))
            .limit(50)
            .all()
        )
        for row in rows:
            validation = row.validation or {}
            if validation.get("total") and validation.get("ok") is False:
                return row.to_legacy_dict()
        return None


def get_latest_cert_history_by_host(host: str):
    with get_session() as session:
        rows = (
            session.query(HistoryEntry)
            .filter(HistoryEntry.host == host)
            .order_by(desc(HistoryEntry.created_at), desc(HistoryEntry.id))
            .limit(50)
            .all()
        )
        for row in rows:
            if "证书切换" in (row.note or ""):
                return row.to_legacy_dict()
        return None


def get_recent_cert_history_by_host(host: str, limit: int = 3):
    with get_session() as session:
        rows = (
            session.query(HistoryEntry)
            .filter(HistoryEntry.host == host)
            .order_by(desc(HistoryEntry.created_at), desc(HistoryEntry.id))
            .limit(100)
            .all()
        )
        out: List[Dict[str, Any]] = []
        for row in rows:
            if "证书切换" in (row.note or ""):
                out.append(row.to_legacy_dict())
                if len(out) >= limit:
                    break
        return out


# ---- server operations ----------------------------------------------


def load_servers():
    with get_session() as session:
        rows = (
            session.query(Server)
            .order_by(desc(Server.updated_at), desc(Server.id))
            .limit(_SERVERS_LIMIT)
            .all()
        )
        return [r.to_legacy_dict() for r in rows]


def save_server(host: str, username: str, note: str = "", password: str = ""):
    with get_session() as session:
        existing = session.query(Server).filter_by(host=host, username=username).one_or_none()
        if existing:
            if note:
                existing.note = note
            if password:
                existing.plain_password = password
            existing.updated_at = datetime.utcnow()
        else:
            srv = Server(
                host=host,
                username=username,
                note=note or "",
                deployed=False,
                status="idle",
            )
            srv.plain_password = password or ""
            session.add(srv)
        session.commit()


def delete_server(host: str, username: str):
    with get_session() as session:
        session.query(Server).filter_by(host=host, username=username).delete()
        session.commit()


def set_server_status(host: str, username: str, deployed: bool):
    with get_session() as session:
        srv = session.query(Server).filter_by(host=host, username=username).one_or_none()
        if srv:
            srv.deployed = bool(deployed)
            srv.status = "deployed" if deployed else "idle"
            session.commit()


def update_server_runtime_status(host: str, username: str, status: str):
    with get_session() as session:
        srv = session.query(Server).filter_by(host=host, username=username).one_or_none()
        if srv:
            srv.status = status or "idle"
            srv.deployed = status == "deployed"
            session.commit()


def set_last_connect_test(host: str, username: str, ok: bool, summary: str):
    with get_session() as session:
        srv = session.query(Server).filter_by(host=host, username=username).one_or_none()
        if srv:
            srv.last_connect_test = {
                "ok": bool(ok),
                "summary": summary,
                "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
            session.commit()


def set_last_availability(host: str, username: str, summary: Dict[str, Any]):
    with get_session() as session:
        srv = session.query(Server).filter_by(host=host, username=username).one_or_none()
        if srv:
            srv.last_availability = {
                "summary": summary or {},
                "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
            session.commit()


# ---- validation helpers (pure, no storage — copied verbatim from legacy) ---


def _humanize_validation_issue(item: Dict[str, Any]) -> str:
    key = item.get("key") or ""
    label = item.get("label") or item.get("key") or "存在异常"
    port = item.get("port")
    mapping = {
        "service_active": "sing-box 服务未正常运行",
        "config_exists": "主配置文件缺失",
        "binary_exists": "sing-box 二进制不可执行",
        "vless_output": "VLESS 节点文件未生成",
        "vmess_output": "VMess 节点文件未生成",
        "hy2_output": "HY2 节点文件未生成",
        "tuic_output": "TUIC 节点文件未生成",
        "trojan_output": "Trojan 节点文件未生成",
        "ss2022_output": "SS2022 节点文件未生成",
        "singbox_output": "Sing-box 配置未生成",
        "mihomo_output": "Mihomo 配置未生成",
    }
    if key in {
        "vless_port_listening",
        "vmess_port_listening",
        "hy2_port_listening",
        "tuic_port_listening",
        "trojan_port_listening",
        "ss2022_port_listening",
    } and port:
        proto = label.split(" ", 1)[0]
        return f"{proto} 端口 {port} 未监听"
    return mapping.get(key, f"{label}异常")


def summarize_validation_issue(validation: Optional[Dict[str, Any]], limit: int = 2) -> str:
    data = validation or {}
    checks = data.get("checks") or []
    priority = {
        "service_active": 1,
        "config_exists": 2,
        "binary_exists": 3,
        "vless_port_listening": 4,
        "vmess_port_listening": 4,
        "hy2_port_listening": 4,
        "tuic_port_listening": 4,
        "trojan_port_listening": 4,
        "ss2022_port_listening": 4,
        "vless_output": 5,
        "vmess_output": 5,
        "hy2_output": 5,
        "tuic_output": 5,
        "trojan_output": 5,
        "ss2022_output": 5,
        "singbox_output": 6,
        "mihomo_output": 6,
    }
    failed = sorted(
        [item for item in checks if not item.get("passed")],
        key=lambda item: (priority.get(item.get("key") or "", 99), item.get("label") or item.get("key") or ""),
    )
    if not failed:
        return ""
    parts = [_humanize_validation_issue(item) for item in failed[: max(1, limit)]]
    return "；".join(parts)
