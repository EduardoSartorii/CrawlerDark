"""
Database session management for SQLAlchemy.

Provides engine creation, session factory, and context-managed
database sessions for repository operations.

Architectural Responsibility:
    Centralizes database connection lifecycle and transaction
    management across the platform.
"""

from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager
from typing import Any

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from phishing_intel.database.models import Base

_engine = None
_SessionFactory: sessionmaker[Session] | None = None


def init_db(database_url: str, echo: bool = False, **engine_kwargs: Any) -> None:
    """
    Initialize database engine and create tables.

    Args:
        database_url: SQLAlchemy database connection URL.
        echo: Enable SQL statement logging.
        **engine_kwargs: Additional engine configuration.
    """
    global _engine, _SessionFactory

    _engine = create_engine(database_url, echo=echo, **engine_kwargs)
    _SessionFactory = sessionmaker(bind=_engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(bind=_engine)


def get_engine():
    """Return the current SQLAlchemy engine instance."""
    if _engine is None:
        raise RuntimeError("Database not initialized. Call init_db() first.")
    return _engine


@contextmanager
def get_session() -> Generator[Session, None, None]:
    """
    Context manager yielding a database session with auto-commit/rollback.

    Yields:
        SQLAlchemy Session instance.

    Raises:
        RuntimeError: If database has not been initialized.
    """
    if _SessionFactory is None:
        raise RuntimeError("Database not initialized. Call init_db() first.")

    session = _SessionFactory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
