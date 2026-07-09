"""
SQLAlchemy Database Models.

These are the persistence models — NOT domain entities.
The infrastructure layer maps between domain entities and these DB models.

Design Pattern: Repository Pattern requires this separation:
    - Domain Entity: business logic, no DB knowledge
    - DB Model: persistence schema, no business logic
    - Repository: maps between the two

SQLAlchemy 2.0 Declarative style with:
    - Async session support (asyncpg/aiosqlite)
    - JSON columns for flexible data storage
    - Proper indexes for CTI query patterns
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.sqlite import JSON
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """SQLAlchemy declarative base for all ORM models."""
    pass


class FindingModel(Base):
    """Persistence model for Finding domain entity."""

    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    source: Mapped[str] = mapped_column(String(256), nullable=False)
    source_type: Mapped[str] = mapped_column(String(64), default="unknown")
    connector: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    category: Mapped[str] = mapped_column(String(64), default="unknown", index=True)
    status: Mapped[str] = mapped_column(String(32), default="new", index=True)

    # Risk
    score_value: Mapped[float] = mapped_column(Float, default=0.0, index=True)
    score_confidence: Mapped[float] = mapped_column(Float, default=0.0)
    severity: Mapped[str] = mapped_column(String(16), default="info", index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)

    # Content
    raw_data: Mapped[str] = mapped_column(Text, default="")
    normalized_data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    metadata_: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, name="metadata")
    tags: Mapped[list[str]] = mapped_column(JSON, default=list)
    tlp: Mapped[str] = mapped_column(String(16), default="WHITE")
    language: Mapped[str] = mapped_column(String(8), default="en")
    fingerprint: Mapped[str] = mapped_column(String(64), default="", index=True)

    # References
    source_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    source_id: Mapped[str | None] = mapped_column(String(256), nullable=True)
    misp_event_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    opencti_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Threat context
    threat_actor: Mapped[str | None] = mapped_column(String(256), nullable=True)
    campaign: Mapped[str | None] = mapped_column(String(256), nullable=True)
    malware_family: Mapped[str | None] = mapped_column(String(256), nullable=True)
    affected_brands: Mapped[list[str]] = mapped_column(JSON, default=list)
    affected_domains: Mapped[list[str]] = mapped_column(JSON, default=list)
    country: Mapped[str | None] = mapped_column(String(8), nullable=True)

    # Relationships
    indicator_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    artifact_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    artifacts: Mapped[list[Any]] = mapped_column(JSON, default=list)
    relationships: Mapped[list[Any]] = mapped_column(JSON, default=list)
    timeline: Mapped[list[Any]] = mapped_column(JSON, default=list)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)

    __table_args__ = (
        Index("ix_findings_score_status", "score_value", "status"),
        Index("ix_findings_connector_created", "connector", "created_at"),
        Index("ix_findings_category_severity", "category", "severity"),
    )


class IndicatorModel(Base):
    """Persistence model for Indicator (IOC) domain entity."""

    __tablename__ = "indicators"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    value: Mapped[str] = mapped_column(String(1024), nullable=False, index=True)
    ioc_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), default="active", index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    source: Mapped[str] = mapped_column(String(256), default="unknown")
    tags: Mapped[list[str]] = mapped_column(JSON, default=list)
    tlp: Mapped[str] = mapped_column(String(16), default="WHITE")
    first_seen: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    description: Mapped[str] = mapped_column(Text, default="")
    metadata_: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, name="metadata")
    related_finding_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)

    __table_args__ = (
        Index("ix_indicators_value_type", "value", "ioc_type", unique=True),
    )
