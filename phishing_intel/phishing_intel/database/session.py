"""Database session and engine management."""

from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, declarative_base, sessionmaker

Base = declarative_base()


def build_engine(database_url: str):
    """Create SQLAlchemy engine with future-compatible settings."""

    return create_engine(database_url, echo=False, future=True)


def build_session_factory(database_url: str) -> sessionmaker[Session]:
    """Create a SQLAlchemy session factory bound to an engine."""

    engine = build_engine(database_url)
    return sessionmaker(bind=engine, autocommit=False, autoflush=False, future=True)


def get_session(factory: sessionmaker[Session]) -> Generator[Session, None, None]:
    """Yield a managed session for repository operations."""

    session = factory()
    try:
        yield session
    finally:
        session.close()
