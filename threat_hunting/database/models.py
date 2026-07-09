"""SQLAlchemy 2 models for relational finding storage."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from sqlalchemy import DateTime, Float, String
from sqlalchemy.dialects.sqlite import JSON
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Base metadata for Alembic migrations."""


class FindingRecord(Base):
    """Relational representation of the Finding aggregate."""

    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str] = mapped_column(String, nullable=False)
    source: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    connector: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    category: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    score: Mapped[float] = mapped_column(Float, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(256), nullable=False, unique=True, index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)

    @classmethod
    def from_payload(
        cls,
        *,
        finding_id: str,
        fingerprint: str,
        created_at: datetime,
        updated_at: datetime,
        payload: dict[str, Any],
    ) -> "FindingRecord":
        """Create a SQLAlchemy record from serialized finding data."""

        return cls(
            id=finding_id,
            title=str(payload["title"]),
            description=str(payload["description"]),
            source=str(payload["source"]),
            connector=str(payload["connector"]),
            category=str(payload["category"]),
            severity=str(payload["severity"]),
            score=float(payload["score"]),
            confidence=float(payload["confidence"]),
            created_at=created_at,
            updated_at=updated_at,
            fingerprint=fingerprint,
            payload=payload,
        )
