"""SQLAlchemy database models for persistence adapters."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, DateTime, Float, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """SQLAlchemy declarative base."""


class FindingRecord(Base):
    """Persistence model for canonical findings."""

    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(String(128), nullable=False)
    connector: Mapped[str] = mapped_column(String(128), nullable=False)
    category: Mapped[str] = mapped_column(String(128), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    raw_data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    normalized_data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict)
    tags: Mapped[list[str]] = mapped_column(JSON, default=list)
    artifacts: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    indicators: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    relationships: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    timeline: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
