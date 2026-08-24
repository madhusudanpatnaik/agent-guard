"""Database engine, session factory, and the FastAPI session dependency."""

from __future__ import annotations

from collections.abc import Iterator

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import get_settings


@event.listens_for(Engine, "connect")
def _enforce_sqlite_foreign_keys(dbapi_connection, connection_record) -> None:
    """Turn on foreign-key enforcement for every SQLite connection.

    SQLite ships with FK enforcement OFF by default, so a plain
    ``db.delete(agent)`` silently orphaned the agent's audit rows on the
    "runs on SQLite out of the box" path — while the same call on the
    documented PostgreSQL backend raised a ForeignKeyViolation (500). That
    split is exactly how the delete-an-audited-agent bug reached production:
    dev and CI ran on the laxer database. Enforcing FKs here makes SQLite
    behave like Postgres, so referential bugs surface in the default path
    instead of only against prod. No-op for non-SQLite backends (the event
    still fires, but the PRAGMA is skipped).
    """
    # `Engine.connect` fires for every backend; only issue the PRAGMA on SQLite.
    if type(dbapi_connection).__module__.startswith("sqlite3") or \
            "sqlite" in type(dbapi_connection).__module__:
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA foreign_keys=ON")
        finally:
            cursor.close()


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""


def _make_engine():
    settings = get_settings()
    connect_args: dict = {}
    kwargs: dict = {}
    if settings.database_url.startswith("sqlite"):
        # Allow use across FastAPI's threadpool for sync endpoints.
        connect_args = {"check_same_thread": False}
    else:
        # Sync endpoints run in the ASGI threadpool and hold a connection for the
        # whole request, so a pool smaller than the worker count silently queues
        # requests and shows up as latency. Size it explicitly rather than
        # inheriting SQLAlchemy's 5+10 default. (SQLite ignores pooling args.)
        kwargs = {
            "pool_size": settings.db_pool_size,
            "max_overflow": settings.db_max_overflow,
            "pool_timeout": settings.db_pool_timeout,
            "pool_recycle": settings.db_pool_recycle,
        }
    return create_engine(
        settings.database_url,
        connect_args=connect_args,
        pool_pre_ping=True,
        future=True,
        **kwargs,
    )


engine = _make_engine()
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)


def init_db() -> None:
    """Create all tables. Idempotent; safe to call on every boot."""
    # Import models so they are registered on ``Base.metadata`` before create_all.
    from . import models  # noqa: F401

    Base.metadata.create_all(bind=engine)


def get_db() -> Iterator[Session]:
    """FastAPI dependency yielding a scoped session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
