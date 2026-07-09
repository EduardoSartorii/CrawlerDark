"""SQLAlchemy ORM entities for phishing intelligence persistence."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, Float, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from phishing_intel.database.session import Base


class Campaign(Base):
    """Represents a correlated phishing campaign."""

    __tablename__ = "campaigns"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    campaign_id: Mapped[str] = mapped_column(String(120), index=True, unique=True)
    score: Mapped[int] = mapped_column(Integer)
    confidence: Mapped[str] = mapped_column(String(20))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(tz=timezone.utc)
    )

    phishing_sites: Mapped[list["PhishingSite"]] = relationship(back_populates="campaign")


class PhishingSite(Base):
    """Represents one phishing URL and associated evidence hashes."""

    __tablename__ = "phishing_sites"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    url: Mapped[str] = mapped_column(Text, index=True)
    domain: Mapped[str] = mapped_column(String(255), index=True)
    html_hash: Mapped[str] = mapped_column(String(64), index=True)
    javascript_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    campaign_id_fk: Mapped[int | None] = mapped_column(ForeignKey("campaigns.id"), nullable=True)

    campaign: Mapped[Campaign | None] = relationship(back_populates="phishing_sites")


class Certificate(Base):
    """SSL certificate metadata extracted from target domain."""

    __tablename__ = "certificates"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    serial_number: Mapped[str] = mapped_column(String(255), index=True)
    issuer: Mapped[str] = mapped_column(Text)
    fingerprint: Mapped[str] = mapped_column(String(128), index=True)
    subject: Mapped[str] = mapped_column(Text)
    san: Mapped[list[str]] = mapped_column(JSON)
    not_before: Mapped[str] = mapped_column(String(80))
    not_after: Mapped[str] = mapped_column(String(80))
    pem: Mapped[str] = mapped_column(Text)


class Infrastructure(Base):
    """Infrastructure profile resolved for one phishing site."""

    __tablename__ = "infrastructures"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ip: Mapped[str] = mapped_column(String(50), index=True)
    asn: Mapped[str | None] = mapped_column(String(50), index=True, nullable=True)
    provider: Mapped[str | None] = mapped_column(String(255), index=True, nullable=True)
    organization: Mapped[str | None] = mapped_column(String(255), nullable=True)
    country: Mapped[str | None] = mapped_column(String(8), nullable=True)
    domain: Mapped[str] = mapped_column(String(255), index=True)


class Fingerprint(Base):
    """Fingerprint hashes used for campaign reuse correlation."""

    __tablename__ = "fingerprints"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    dom_hash: Mapped[str] = mapped_column(String(64), index=True)
    asset_hash: Mapped[str] = mapped_column(String(64), index=True)
    script_hash: Mapped[str] = mapped_column(String(64), index=True)
    campaign_fingerprint: Mapped[str] = mapped_column(String(64), index=True)


class MispEvent(Base):
    """MISP event mapping for local campaign/event persistence."""

    __tablename__ = "misp_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_uuid: Mapped[str] = mapped_column(String(80), index=True)
    event_id: Mapped[str] = mapped_column(String(80), index=True)
    campaign_id: Mapped[str] = mapped_column(String(120), index=True)


class EvidenceAudit(Base):
    """Chain-of-custody evidence and processing audit trail."""

    __tablename__ = "evidence_audit"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    url: Mapped[str] = mapped_column(Text)
    html_hash: Mapped[str] = mapped_column(String(64))
    javascript_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    ssl_fingerprint: Mapped[str | None] = mapped_column(String(128), nullable=True)
    raw_html: Mapped[str] = mapped_column(Text)
    raw_javascript: Mapped[list[str]] = mapped_column(JSON)
    analysis_result: Mapped[dict[str, str | int | float | list[str]]] = mapped_column(JSON)


class ProfileComparison(Base):
    """Stores desktop/mobile rendering differences for future correlation."""

    __tablename__ = "profile_comparisons"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    url: Mapped[str] = mapped_column(Text, index=True)
    profile_name: Mapped[str] = mapped_column(String(80), index=True)
    dom_hash: Mapped[str] = mapped_column(String(64), index=True)
    asset_hash: Mapped[str] = mapped_column(String(64))
    script_hash: Mapped[str] = mapped_column(String(64))
    dom_diff: Mapped[dict[str, list[str]]] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(tz=timezone.utc)
    )
