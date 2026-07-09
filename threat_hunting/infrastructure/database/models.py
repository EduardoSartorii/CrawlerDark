"""
SQLAlchemy ORM Models
=====================

Persistence models for the Threat Hunting Platform.
ORM models are infrastructure detail — they are never exposed to the Core.
Repositories translate between ORM models and domain entities.

Architecture decisions:
    - JSON columns store complex nested data (metadata, normalized_data, etc.).
    - All primary keys are UUIDs (strings) for portability.
    - Timestamps are stored as UTC.
    - Soft-delete is NOT used — dismissed Findings keep their status field.
    - Indexes are created on the most common query predicates.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column

from threat_hunting.infrastructure.database.session import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


class FindingModel(Base):
    """ORM model for the Finding aggregate."""

    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    connector: Mapped[str] = mapped_column(String(64), nullable=False)
    category: Mapped[str] = mapped_column(String(64), nullable=False, default="general")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="raw")
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="info")
    score_value: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    score_confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    source_published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    raw_data: Mapped[str | None] = mapped_column(Text, nullable=True)
    normalized_data_json: Mapped[str] = mapped_column(Text, default="{}")
    metadata_json: Mapped[str] = mapped_column(Text, default="{}")
    tags_json: Mapped[str] = mapped_column(Text, default="[]")
    indicators_json: Mapped[str] = mapped_column(Text, default="[]")
    relationships_json: Mapped[str] = mapped_column(Text, default="[]")
    detection_results_json: Mapped[str] = mapped_column(Text, default="[]")
    artifacts_json: Mapped[str] = mapped_column(Text, default="[]")
    export_log_json: Mapped[str] = mapped_column(Text, default="{}")
    timeline_json: Mapped[str] = mapped_column(Text, default="[]")
    source_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    source_id: Mapped[str | None] = mapped_column(String(256), nullable=True)
    duplicate_of: Mapped[str | None] = mapped_column(String(36), nullable=True)
    correlation_group: Mapped[str | None] = mapped_column(String(36), nullable=True)
    content_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)

    __table_args__ = (
        Index("ix_findings_connector", "connector"),
        Index("ix_findings_category", "category"),
        Index("ix_findings_severity", "severity"),
        Index("ix_findings_created_at", "created_at"),
        Index("ix_findings_score", "score_value"),
        Index("ix_findings_source_id", "connector", "source_id"),
    )


class IndicatorModel(Base):
    """ORM model for the Indicator entity."""

    __tablename__ = "indicators"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    type: Mapped[str] = mapped_column(String(32), nullable=False)
    value: Mapped[str] = mapped_column(String(1024), nullable=False)
    context: Mapped[str | None] = mapped_column(String(256), nullable=True)
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    tags_json: Mapped[str] = mapped_column(Text, default="[]")
    sources_json: Mapped[str] = mapped_column(Text, default="[]")
    finding_ids_json: Mapped[str] = mapped_column(Text, default="[]")
    enrichment_json: Mapped[str] = mapped_column(Text, default="{}")
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    is_whitelisted: Mapped[bool] = mapped_column(Boolean, default=False)
    is_blacklisted: Mapped[bool] = mapped_column(Boolean, default=False)
    metadata_json: Mapped[str] = mapped_column(Text, default="{}")

    __table_args__ = (
        Index("ix_indicators_type_value", "type", "value", unique=True),
        Index("ix_indicators_type", "type"),
    )


class KeywordModel(Base):
    """ORM model for Keyword entities."""

    __tablename__ = "keywords"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    value: Mapped[str] = mapped_column(String(512), nullable=False)
    type: Mapped[str] = mapped_column(String(32), nullable=False, default="plain")
    description: Mapped[str] = mapped_column(Text, default="")
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    case_sensitive: Mapped[bool] = mapped_column(Boolean, default=False)
    watchlist_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    tags_json: Mapped[str] = mapped_column(Text, default="[]")
    match_count: Mapped[int] = mapped_column(Integer, default=0)
    last_match: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    metadata_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class VIPModel(Base):
    """ORM model for VIP entities."""

    __tablename__ = "vips"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    type: Mapped[str] = mapped_column(String(32), nullable=False, default="person")
    description: Mapped[str] = mapped_column(Text, default="")
    organization: Mapped[str | None] = mapped_column(String(256), nullable=True)
    role: Mapped[str | None] = mapped_column(String(128), nullable=True)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    emails_json: Mapped[str] = mapped_column(Text, default="[]")
    aliases_json: Mapped[str] = mapped_column(Text, default="[]")
    domains_json: Mapped[str] = mapped_column(Text, default="[]")
    social_handles_json: Mapped[str] = mapped_column(Text, default="{}")
    phones_json: Mapped[str] = mapped_column(Text, default="[]")
    tags_json: Mapped[str] = mapped_column(Text, default="[]")
    alert_on_mention: Mapped[bool] = mapped_column(Boolean, default=True)
    match_count: Mapped[int] = mapped_column(Integer, default=0)
    last_match: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    metadata_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class ThreatActorModel(Base):
    """ORM model for ThreatActor entities."""

    __tablename__ = "threat_actors"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(256), nullable=False, unique=True)
    aliases_json: Mapped[str] = mapped_column(Text, default="[]")
    description: Mapped[str] = mapped_column(Text, default="")
    motivation_json: Mapped[str] = mapped_column(Text, default="[]")
    capability: Mapped[str | None] = mapped_column(String(64), nullable=True)
    country: Mapped[str | None] = mapped_column(String(64), nullable=True)
    sectors_targeted_json: Mapped[str] = mapped_column(Text, default="[]")
    ttps_json: Mapped[str] = mapped_column(Text, default="[]")
    associated_indicators_json: Mapped[str] = mapped_column(Text, default="[]")
    associated_campaigns_json: Mapped[str] = mapped_column(Text, default="[]")
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    tags_json: Mapped[str] = mapped_column(Text, default="[]")
    references_json: Mapped[str] = mapped_column(Text, default="[]")
    metadata_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class RuleModel(Base):
    """ORM model for detection Rule entities."""

    __tablename__ = "rules"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    type: Mapped[str] = mapped_column(String(32), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    pattern: Mapped[str | None] = mapped_column(Text, nullable=True)
    content: Mapped[str | None] = mapped_column(Text, nullable=True)
    ioc_list_json: Mapped[str] = mapped_column(Text, default="[]")
    sub_rules_json: Mapped[str] = mapped_column(Text, default="[]")
    operator: Mapped[str] = mapped_column(String(8), default="and")
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    priority: Mapped[int] = mapped_column(Integer, default=50)
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    score_contribution: Mapped[float] = mapped_column(Float, default=1.0)
    categories_json: Mapped[str] = mapped_column(Text, default="[]")
    tags_json: Mapped[str] = mapped_column(Text, default="[]")
    match_count: Mapped[int] = mapped_column(Integer, default=0)
    false_positive_count: Mapped[int] = mapped_column(Integer, default=0)
    last_match: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    metadata_json: Mapped[str] = mapped_column(Text, default="{}")
    author: Mapped[str] = mapped_column(String(128), default="system")
    version: Mapped[str] = mapped_column(String(16), default="1.0.0")
    references_json: Mapped[str] = mapped_column(Text, default="[]")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class ConnectorConfigModel(Base):
    """ORM model for ConnectorConfig entities."""

    __tablename__ = "connector_configs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    connector_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    source_type: Mapped[str] = mapped_column(String(64), nullable=False)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    opsec_profile: Mapped[str] = mapped_column(String(64), default="standard")
    credentials_json: Mapped[str] = mapped_column(Text, default="{}")
    params_json: Mapped[str] = mapped_column(Text, default="{}")
    tags_json: Mapped[str] = mapped_column(Text, default="[]")
    schedule: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_run: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_success: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    run_count: Mapped[int] = mapped_column(Integer, default=0)
    error_count: Mapped[int] = mapped_column(Integer, default=0)
    findings_produced: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
