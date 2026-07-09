"""SQLAlchemy persistence models.

The schema stores the canonical finding JSON document and its stable hash. This
keeps migrations simple while allowing richer graph/search stores to be added as
independent adapters.
"""

from __future__ import annotations

from sqlalchemy import JSON, DateTime, Float, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """SQLAlchemy declarative base."""


class FindingRecord(Base):
    """Relational representation of a canonical finding."""

    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    content_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    title: Mapped[str] = mapped_column(String(512), index=True)
    source: Mapped[str] = mapped_column(String(128), index=True)
    connector: Mapped[str] = mapped_column(String(128), index=True)
    category: Mapped[str] = mapped_column(String(128), index=True)
    severity: Mapped[str] = mapped_column(String(32), index=True)
    score: Mapped[float] = mapped_column(Float, default=0.0)
    description: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[object] = mapped_column(DateTime(timezone=True), index=True)
    updated_at: Mapped[object] = mapped_column(DateTime(timezone=True), index=True)
    payload: Mapped[dict] = mapped_column(JSON)
