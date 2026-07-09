"""SQLAlchemy ORM models.

Responsibility
--------------
Define the relational schema used by the SQL backends (SQLite/PostgreSQL). The
canonical :class:`Finding` is stored with its scalar fields as columns (for
indexing/filtering) and its nested collections (indicators, artifacts,
relationships, timeline, raw/normalized data, metadata) as JSON, so the schema
stays stable as the domain evolves. Mapping between ORM rows and domain objects
lives in the repository, keeping the ORM out of the domain.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, Float, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""


class FindingRow(Base):
    """Relational representation of a :class:`Finding` aggregate."""

    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    title: Mapped[str] = mapped_column(String(512))
    description: Mapped[str] = mapped_column(Text, default="")
    source: Mapped[str] = mapped_column(String(128), index=True)
    connector: Mapped[str] = mapped_column(String(64), index=True)
    category: Mapped[str] = mapped_column(String(64), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    score: Mapped[float] = mapped_column(Float, index=True, default=0.0)
    confidence: Mapped[str] = mapped_column(String(16), default="unknown")
    fingerprint: Mapped[str | None] = mapped_column(String(64), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    document: Mapped[dict] = mapped_column(JSON)
