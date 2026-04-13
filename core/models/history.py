"""Deployment / operation history — replaces ``data/deploy_history.json``.

One row per logged event. The flexible bits (``nodes``, ``ports``,
``validation``) are stored as JSON columns so we don't have to reshape every
insert when sing-box output format changes.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy import DateTime, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from core.db import Base


class HistoryEntry(Base):
    __tablename__ = "history_entries"

    # Surrogate primary key plus the original UUID that app.py refers to.
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    entry_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)

    host: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    username: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    note: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow, index=True)

    node_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    nodes: Mapped[Optional[List[Dict[str, Any]]]] = mapped_column(JSON, nullable=True)
    ports: Mapped[Optional[List[str]]] = mapped_column(JSON, nullable=True)
    validation: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    error: Mapped[str] = mapped_column(Text, nullable=False, default="")

    # ---- serialization compatible with legacy history.json ---------

    def to_legacy_dict(self) -> Dict[str, Any]:
        return {
            "id": self.entry_id,
            "host": self.host,
            "username": self.username,
            "note": self.note,
            "status": self.status,
            "created_at": self.created_at.strftime("%Y-%m-%d %H:%M:%S")
            if isinstance(self.created_at, datetime)
            else str(self.created_at or ""),
            "node_count": self.node_count or 0,
            "nodes": self.nodes or [],
            "ports": self.ports or [],
            "validation": self.validation or {},
            "error": self.error or "",
        }

    def __repr__(self) -> str:
        return f"<HistoryEntry id={self.id} host={self.host} status={self.status}>"
