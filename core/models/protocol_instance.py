"""Per-VPS protocol instance record.

Each row represents one inbound currently installed on one VPS. The row
stores the parameters used to build the inbound (port, UUID, keys, etc.)
as a JSON column so schema changes don't require migrations when sing-box
adds new protocol fields.

Relationship: many ``ProtocolInstance`` rows per one ``Server`` row. We
don't currently use a SQLAlchemy back-reference because Server doesn't
need to eager-load protocol lists on every query — use a direct query
when you need them.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional

from sqlalchemy import DateTime, ForeignKey, Integer, JSON, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from core.db import Base


class ProtocolInstance(Base):
    __tablename__ = "protocol_instances"
    __table_args__ = (
        UniqueConstraint("server_id", "tag", name="uq_proto_server_tag"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    server_id: Mapped[int] = mapped_column(
        ForeignKey("servers.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # Canonical protocol name, matches ProtocolSpec.name ("vless_reality", ...)
    proto: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    # sing-box inbound tag — unique per server so we can address it for
    # update/delete without ambiguity.
    tag: Mapped[str] = mapped_column(String(64), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False)

    # User-editable parameter dict (uuid, sni, private_key, ...)
    params: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    # Runtime status: "running" | "stopped" | "error" | "unknown"
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="unknown")
    last_error: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "server_id": self.server_id,
            "proto": self.proto,
            "tag": self.tag,
            "port": self.port,
            "params": dict(self.params or {}),
            "status": self.status,
            "last_error": self.last_error,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    def __repr__(self) -> str:
        return f"<ProtocolInstance id={self.id} server_id={self.server_id} {self.proto}:{self.port}>"
