"""Engine and session lifecycle.

Synchronous SQLAlchemy is used deliberately. FastAPI runs sync dependencies in
a worker threadpool, so throughput is adequate at this scale, and sync sessions
avoid a class of event-loop and greenlet errors that would be difficult to
diagnose in an environment where the stack cannot be run locally.
"""

from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings, get_settings


def build_engine(settings: Settings) -> Engine:
    url = settings.DATABASE_URL
    if url.startswith("sqlite"):
        from sqlalchemy.pool import StaticPool

        engine = create_engine(
            url,
            future=True,
            echo=False,
            connect_args={"check_same_thread": False},
            # One shared connection so an in-memory database survives across
            # sessions within a single test.
            poolclass=StaticPool,
        )

        @event.listens_for(engine, "connect")
        def _sqlite_pragmas(dbapi_connection, _record):  # pragma: no cover
            cursor = dbapi_connection.cursor()
            # SQLite ignores foreign keys unless explicitly told not to, which
            # would let RBAC/ownership tests pass against invalid rows.
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

        return engine

    return create_engine(
        url,
        future=True,
        echo=False,
        pool_pre_ping=True,   # drop connections severed by a container restart
        pool_size=10,
        max_overflow=20,
        pool_recycle=1800,
    )


_engine: Engine | None = None
_SessionLocal: sessionmaker[Session] | None = None


def get_engine() -> Engine:
    global _engine
    if _engine is None:
        _engine = build_engine(get_settings())
    return _engine


def get_session_factory() -> sessionmaker[Session]:
    global _SessionLocal
    if _SessionLocal is None:
        _SessionLocal = sessionmaker(
            bind=get_engine(),
            autoflush=False,
            autocommit=False,
            expire_on_commit=False,
        )
    return _SessionLocal


def get_db() -> Generator[Session]:
    """FastAPI dependency: one session per request, always closed.

    The session is not committed here. Routes commit explicitly so a handler
    that raises after a partial write cannot leave it persisted.
    """
    session = get_session_factory()()
    try:
        yield session
    finally:
        session.close()


def reset_engine_for_tests() -> None:
    """Drop cached engine/session factory so a test can rebind configuration."""
    global _engine, _SessionLocal
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _SessionLocal = None
