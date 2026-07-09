"""Modelos SQLAlchemy 2 (ORM async).

Nota arquitetural: estes modelos NÃO são as entidades de domínio. Existem
mappers (em ``mappers.py``) que traduzem em ambos os sentidos. Isso mantém
o domínio puro (sem imports de SQLAlchemy).
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.types import TypeDecorator


class GUID(TypeDecorator[UUID]):
    """Type-agnostic UUID (armazenado como string 36 em qualquer DB)."""

    impl = String(36)
    cache_ok = True

    def process_bind_param(self, value: UUID | str | None, dialect) -> str | None:  # type: ignore[override,no-untyped-def]
        if value is None:
            return None
        return str(value)

    def process_result_value(self, value: str | None, dialect) -> UUID | None:  # type: ignore[override,no-untyped-def]
        if value is None:
            return None
        return UUID(value)


class Base(DeclarativeBase):
    pass


class FindingModel(Base):
    __tablename__ = "findings"

    id: Mapped[UUID] = mapped_column(GUID(), primary_key=True, default=uuid4)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    source: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    connector: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    author: Mapped[str | None] = mapped_column(String(256), nullable=True)
    category: Mapped[str] = mapped_column(String(60), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    score: Mapped[float] = mapped_column(Float, default=0.0, index=True)
    confidence: Mapped[int] = mapped_column(Integer, default=50)
    tlp: Mapped[str] = mapped_column(String(16), default="AMBER")
    dedup_hash: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    raw_data: Mapped[dict] = mapped_column(JSON, default=dict)
    normalized_data: Mapped[dict] = mapped_column(JSON, default=dict)
    metadata_: Mapped[dict] = mapped_column("metadata", JSON, default=dict)
    tags: Mapped[list] = mapped_column(JSON, default=list)
    artifacts: Mapped[list] = mapped_column(JSON, default=list)
    relationships_json: Mapped[list] = mapped_column("relationships", JSON, default=list)
    timeline: Mapped[list] = mapped_column(JSON, default=list)
    exported_to: Mapped[list] = mapped_column(JSON, default=list)

    indicators: Mapped[list["IndicatorModel"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan", lazy="selectin"
    )


class IndicatorModel(Base):
    __tablename__ = "indicators"

    id: Mapped[UUID] = mapped_column(GUID(), primary_key=True, default=uuid4)
    finding_id: Mapped[UUID] = mapped_column(
        GUID(), ForeignKey("findings.id", ondelete="CASCADE"), index=True
    )
    type: Mapped[str] = mapped_column(String(60), nullable=False, index=True)
    value: Mapped[str] = mapped_column(String(1024), nullable=False, index=True)
    confidence: Mapped[int] = mapped_column(Integer, default=50)
    tags: Mapped[list] = mapped_column(JSON, default=list)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    context: Mapped[dict] = mapped_column(JSON, default=dict)

    finding: Mapped[FindingModel] = relationship(back_populates="indicators")


class ThreatActorModel(Base):
    __tablename__ = "threat_actors"

    id: Mapped[UUID] = mapped_column(GUID(), primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(256), nullable=False, unique=True, index=True)
    aliases: Mapped[list] = mapped_column(JSON, default=list)
    description: Mapped[str] = mapped_column(Text, default="")
    motivations: Mapped[list] = mapped_column(JSON, default=list)
    countries: Mapped[list] = mapped_column(JSON, default=list)
    tags: Mapped[list] = mapped_column(JSON, default=list)
    context: Mapped[dict] = mapped_column(JSON, default=dict)


class WatchlistItemModel(Base):
    __tablename__ = "watchlist_items"

    id: Mapped[UUID] = mapped_column(GUID(), primary_key=True, default=uuid4)
    kind: Mapped[str] = mapped_column(String(60), nullable=False, index=True)
    value: Mapped[str] = mapped_column(String(500), nullable=False, index=True)
    aliases: Mapped[list] = mapped_column(JSON, default=list)
    tags: Mapped[list] = mapped_column(JSON, default=list)
    enabled: Mapped[bool] = mapped_column(default=True)
    context: Mapped[dict] = mapped_column(JSON, default=dict)


class DetectionRuleModel(Base):
    __tablename__ = "detection_rules"

    id: Mapped[UUID] = mapped_column(GUID(), primary_key=True, default=uuid4)
    rule_id: Mapped[str] = mapped_column(String(120), nullable=False, unique=True, index=True)
    kind: Mapped[str] = mapped_column(String(60), nullable=False)
    pattern: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    category: Mapped[str] = mapped_column(String(60), default="OTHER")
    severity: Mapped[str] = mapped_column(String(16), default="MEDIUM")
    confidence: Mapped[int] = mapped_column(Integer, default=50)
    tags: Mapped[list] = mapped_column(JSON, default=list)
    enabled: Mapped[bool] = mapped_column(default=True)
    depends_on: Mapped[list] = mapped_column(JSON, default=list)


class JobModel(Base):
    __tablename__ = "jobs"

    id: Mapped[UUID] = mapped_column(GUID(), primary_key=True, default=uuid4)
    connector: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(30), nullable=False, index=True)
    items_collected: Mapped[int] = mapped_column(Integer, default=0)
    items_persisted: Mapped[int] = mapped_column(Integer, default=0)
    errors: Mapped[list] = mapped_column(JSON, default=list)
    metadata_: Mapped[dict] = mapped_column("metadata", JSON, default=dict)
