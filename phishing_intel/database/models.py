"""
SQLAlchemy ORM models for phishing intelligence persistence.

Defines database tables for campaigns, phishing sites, certificates,
infrastructure, fingerprints, and MISP event tracking.

Architectural Responsibility:
    Data persistence layer mapping analysis results to relational
    storage for historical correlation and audit trails.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, Float, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""

    pass


class CampaignModel(Base):
    """Campaigns table - aggregates related phishing incidents."""

    __tablename__ = "campaigns"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    campaign_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    score: Mapped[float] = mapped_column(Float, default=0.0)
    confidence: Mapped[str] = mapped_column(String(16), default="low")
    target_brand: Mapped[str] = mapped_column(String(128), default="")
    phishing_type: Mapped[str] = mapped_column(String(64), default="")
    kit_fingerprint: Mapped[str] = mapped_column(String(64), default="", index=True)
    incident_count: Mapped[int] = mapped_column(Integer, default=0)
    tags: Mapped[str] = mapped_column(Text, default="[]")
    metadata_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )


class PhishingSiteModel(Base):
    """Phishing sites table - individual analyzed URLs."""

    __tablename__ = "phishing_sites"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    url: Mapped[str] = mapped_column(String(2048), index=True)
    domain: Mapped[str] = mapped_column(String(256), index=True)
    html_hash: Mapped[str] = mapped_column(String(64), index=True)
    javascript_hash: Mapped[str] = mapped_column(String(64), default="")
    campaign_id: Mapped[str] = mapped_column(String(64), default="", index=True)
    phishing_type: Mapped[str] = mapped_column(String(64), default="")
    target_brand: Mapped[str] = mapped_column(String(128), default="")
    analysis_json: Mapped[str] = mapped_column(Text, default="{}")
    evidence_path: Mapped[str] = mapped_column(String(512), default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )


class CertificateModel(Base):
    """SSL certificates table for infrastructure correlation."""

    __tablename__ = "certificates"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    serial_number: Mapped[str] = mapped_column(String(128), index=True)
    issuer: Mapped[str] = mapped_column(String(512), default="")
    subject: Mapped[str] = mapped_column(String(512), default="")
    sha1_fingerprint: Mapped[str] = mapped_column(String(40), index=True)
    sha256_fingerprint: Mapped[str] = mapped_column(String(64), default="")
    san: Mapped[str] = mapped_column(Text, default="[]")
    not_before: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    not_after: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    raw_pem: Mapped[str] = mapped_column(Text, default="")
    site_url: Mapped[str] = mapped_column(String(2048), default="")


class InfrastructureModel(Base):
    """Hosting infrastructure table."""

    __tablename__ = "infrastructures"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ip: Mapped[str] = mapped_column(String(45), index=True)
    domain: Mapped[str] = mapped_column(String(256), default="", index=True)
    asn: Mapped[str] = mapped_column(String(32), index=True)
    organization: Mapped[str] = mapped_column(String(256), default="")
    provider: Mapped[str] = mapped_column(String(256), default="")
    country: Mapped[str] = mapped_column(String(8), default="")


class FingerprintModel(Base):
    """Kit fingerprints table for campaign correlation."""

    __tablename__ = "fingerprints"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    dom_hash: Mapped[str] = mapped_column(String(64), index=True)
    asset_hash: Mapped[str] = mapped_column(String(64), default="")
    script_hash: Mapped[str] = mapped_column(String(64), index=True)
    campaign_fingerprint: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    site_url: Mapped[str] = mapped_column(String(2048), default="")


class MISPEventModel(Base):
    """MISP event tracking table."""

    __tablename__ = "misp_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_uuid: Mapped[str] = mapped_column(String(36), unique=True, index=True)
    event_id: Mapped[int] = mapped_column(Integer, default=0)
    site_url: Mapped[str] = mapped_column(String(2048), default="")
    campaign_id: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
