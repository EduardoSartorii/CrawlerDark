"""Database engine and session management."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from threat_hunting.database.models import Base


def create_sqlalchemy_engine(database_url: str):
    """Create SQLAlchemy engine and ensure schema is initialized."""
    if database_url.startswith("sqlite:///"):
        db_path = database_url.replace("sqlite:///", "", 1)
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(database_url, future=True)
    Base.metadata.create_all(engine)
    return engine


def create_session_factory(database_url: str) -> sessionmaker[Session]:
    """Create SQLAlchemy session factory."""
    engine = create_sqlalchemy_engine(database_url)
    return sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
