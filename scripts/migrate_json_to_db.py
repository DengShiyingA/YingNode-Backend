#!/usr/bin/env python3
"""Migrate legacy ``data/servers.json`` + ``data/deploy_history.json`` to SQLite.

Idempotent — safe to run multiple times. Each existing row is upserted by
its natural key (``host+username`` for servers, UUID for history entries).
Rows already present in the DB are skipped, never overwritten.

Run from the project root::

    python3 scripts/migrate_json_to_db.py

If no JSON files exist the script prints that and exits cleanly.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from core.db import get_session, init_db  # noqa: E402
from core.models import HistoryEntry, Server  # noqa: E402


SERVERS_JSON = BASE_DIR / "data" / "servers.json"
HISTORY_JSON = BASE_DIR / "data" / "deploy_history.json"


def _parse_iso(value: str) -> datetime:
    if not value:
        return datetime.utcnow()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    return datetime.utcnow()


def migrate_servers() -> int:
    if not SERVERS_JSON.exists():
        print(f"[skip] {SERVERS_JSON.name}: not found")
        return 0

    try:
        items = json.loads(SERVERS_JSON.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"[error] reading {SERVERS_JSON.name}: {exc}")
        return 0

    inserted = 0
    with get_session() as session:
        for item in items:
            host = (item.get("host") or "").strip()
            username = (item.get("username") or "").strip()
            if not host or not username:
                continue

            existing = session.query(Server).filter_by(host=host, username=username).one_or_none()
            if existing:
                continue

            srv = Server(
                host=host,
                username=username,
                note=item.get("note") or "",
                deployed=bool(item.get("deployed", False)),
                status=item.get("status") or ("deployed" if item.get("deployed") else "idle"),
                last_connect_test=item.get("last_connect_test") or None,
                last_availability=item.get("last_availability") or None,
            )
            # Plaintext password → encrypted at rest via setter.
            srv.plain_password = item.get("password") or ""
            session.add(srv)
            inserted += 1
        session.commit()

    print(f"[ok] servers.json → DB: inserted {inserted} new rows")
    return inserted


def migrate_history() -> int:
    if not HISTORY_JSON.exists():
        print(f"[skip] {HISTORY_JSON.name}: not found")
        return 0

    try:
        items = json.loads(HISTORY_JSON.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"[error] reading {HISTORY_JSON.name}: {exc}")
        return 0

    inserted = 0
    with get_session() as session:
        for item in items:
            entry_id = (item.get("id") or "").strip()
            if not entry_id:
                continue

            existing = session.query(HistoryEntry).filter_by(entry_id=entry_id).one_or_none()
            if existing:
                continue

            entry = HistoryEntry(
                entry_id=entry_id,
                host=(item.get("host") or "").strip(),
                username=item.get("username") or "",
                note=item.get("note") or "",
                status=item.get("status") or "",
                created_at=_parse_iso(item.get("created_at") or ""),
                node_count=int(item.get("node_count") or 0),
                nodes=item.get("nodes") or [],
                ports=item.get("ports") or [],
                validation=item.get("validation") or {},
                error=item.get("error") or "",
            )
            session.add(entry)
            inserted += 1
        session.commit()

    print(f"[ok] deploy_history.json → DB: inserted {inserted} new rows")
    return inserted


def main() -> int:
    init_db()
    total = migrate_servers() + migrate_history()
    print(f"[done] migrated {total} rows total")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
