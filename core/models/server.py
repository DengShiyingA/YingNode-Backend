"""Remote VPS record — replaces ``data/servers.json``.

The SSH password is encrypted at rest via ``core.crypto.encrypt_secret`` and
decrypted only when a deploy/uninstall job runs. Read the ``password`` attr
via the ``plain_password`` property; the raw column value is ciphertext.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional

from sqlalchemy import Boolean, DateTime, Integer, JSON, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from core.crypto import decrypt_secret, encrypt_secret
from core.db import Base


class Server(Base):
    __tablename__ = "servers"
    __table_args__ = (
        UniqueConstraint("host", "username", name="uq_server_host_user"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    host: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    username: Mapped[str] = mapped_column(String(64), nullable=False)
    password_encrypted: Mapped[str] = mapped_column(String(1024), nullable=False, default="")
    note: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    deployed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="idle")

    last_connect_test: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    last_availability: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    # ---- password helpers ------------------------------------------

    @property
    def plain_password(self) -> str:
        return decrypt_secret(self.password_encrypted or "")

    @plain_password.setter
    def plain_password(self, value: str) -> None:
        self.password_encrypted = encrypt_secret(value or "")

    # ---- serialization compatible with legacy servers.json ----------

    def to_legacy_dict(self) -> Dict[str, Any]:
        """Return a dict matching the pre-DB ``servers.json`` shape so
        existing code paths (and the iOS client) continue to work without
        change."""
        return {
            "host": self.host,
            "username": self.username,
            "password": self.plain_password,
            "note": self.note,
            "deployed": bool(self.deployed),
            "status": self.status or ("deployed" if self.deployed else "idle"),
            "last_connect_test": self.last_connect_test or {},
            "last_availability": self.last_availability or {},
        }

    def __repr__(self) -> str:
        return f"<Server id={self.id} {self.username}@{self.host} deployed={self.deployed}>"
