"""
OwlScan Database — Persistent Signal Storage

Author:  packetsn1ffer
AI:      Claude (Anthropic)
License: MIT — see LICENSE
"""
from __future__ import annotations

from contextlib import contextmanager
from typing import Generator

from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from owlscan.core.config import config
from owlscan.core.models import Base

_engine = None
_SessionFactory = None


def get_engine():
    global _engine
    if _engine is None:
        db_url = config.get("database", "url", default="sqlite:///owlscan.db")
        kwargs = {}
        if db_url.startswith("sqlite"):
            kwargs["check_same_thread"] = False
        _engine = create_engine(
            db_url,
            echo=config.get("database", "echo", default=False),
            pool_size=config.get("database", "pool_size", default=5)
            if not db_url.startswith("sqlite")
            else None or 5,
            connect_args=kwargs if db_url.startswith("sqlite") else {},
        )
        if db_url.startswith("sqlite"):
            @event.listens_for(_engine, "connect")
            def set_sqlite_pragma(dbapi_conn, _):
                cursor = dbapi_conn.cursor()
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.execute("PRAGMA synchronous=NORMAL")
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.close()
    return _engine


def get_session_factory():
    global _SessionFactory
    if _SessionFactory is None:
        _SessionFactory = sessionmaker(bind=get_engine(), expire_on_commit=False)
    return _SessionFactory


def init_db() -> None:
    """Initialize the shadow network database — create all tables."""
    Base.metadata.create_all(bind=get_engine())


def drop_db() -> None:
    """Wipe the grid — destroys all data. Non-reversible."""
    Base.metadata.drop_all(bind=get_engine())


@contextmanager
def get_db() -> Generator[Session, None, None]:
    """Context manager for database sessions."""
    factory = get_session_factory()
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_db_session() -> Session:
    """Get a raw session — caller is responsible for commit/close."""
    return get_session_factory()()
