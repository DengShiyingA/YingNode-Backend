"""SQLAlchemy engine, session factory, declarative base.

Usage::

    from core.db import get_session, init_db

    init_db()  # called once at app startup
    with get_session() as session:
        session.add(obj)
        session.commit()
"""
from __future__ import annotations

import os
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


_BASE_DIR = Path(__file__).resolve().parent.parent
_DEFAULT_DB_PATH = _BASE_DIR / "data" / "yingnode.db"


def _database_url() -> str:
    env = os.environ.get("YINGNODE_DATABASE_URL", "").strip()
    if env:
        return env
    _DEFAULT_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    return f"sqlite:///{_DEFAULT_DB_PATH}"


# Engine is module-level so tests and migrations share the same connection
# pool. SQLite + check_same_thread=False is required because Flask serves
# requests on a pool of threads.
_engine = create_engine(
    _database_url(),
    connect_args={"check_same_thread": False}
    if _database_url().startswith("sqlite")
    else {},
    future=True,
)

_SessionLocal = sessionmaker(
    bind=_engine,
    autoflush=False,
    autocommit=False,
    future=True,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    """Root declarative class for all ORM models."""


@contextmanager
def get_session() -> Iterator[Session]:
    """Context-managed session with automatic rollback on exception.

    Callers are responsible for calling ``session.commit()`` — the context
    manager only guarantees cleanup on exit.
    """
    session = _SessionLocal()
    try:
        yield session
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def init_db() -> None:
    """Create all tables. Idempotent — safe to call on every boot."""
    # Importing models here registers them with Base.metadata before create_all.
    from core.models import User, Server, HistoryEntry, ProtocolInstance  # noqa: F401

    Base.metadata.create_all(bind=_engine)
