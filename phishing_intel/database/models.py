"""SQLAlchemy persistence models for phishing campaign history."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Declarative base for all phishing intelligence tables."""


class CampaignORM(Base):
    """Persisted campaign attribution summary."""

    __tablename__ = "campaigns"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    campaign_id: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    score: Mapped[int] = mapped_column(Integer)
    confidence: Mapped[str] = mapped_column(String(32))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(UTC))
    sites: Mapped[list["PhishingSiteORM"]] = relationship(back_populates="campaign")


class PhishingSiteORM(Base):
    """Persisted phishing site and artifact hashes."""

    __tablename__ = "phishing_sites"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    campaign_pk: Mapped[int | None] = mapped_column(ForeignKey("campaigns.id"))
    url: Mapped[str | None] = mapped_column(Text)
    domain: Mapped[str | None] = mapped_column(String(255), index=True)
    html_hash: Mapped[str | None] = mapped_column(String(64), index=True)
    javascript_hash: Mapped[str | None] = mapped_column(String(64))
    phishing_type: Mapped[str | None] = mapped_column(String(64))
    target_brand: Mapped[str | None] = mapped_column(String(128), index=True)
    campaign: Mapped[CampaignORM | None] = relationship(back_populates="sites")


class CertificateORM(Base):
    """Persisted x509 certificate metadata."""

    __tablename__ = "certificates"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    serial_number: Mapped[str | None] = mapped_column(String(128), index=True)
    issuer: Mapped[str | None] = mapped_column(Text)
    fingerprint: Mapped[str | None] = mapped_column(String(128), index=True)
    pem: Mapped[str | None] = mapped_column(Text)


class InfrastructureORM(Base):
    """Persisted hosting and ASN context."""

    __tablename__ = "infrastructures"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ip: Mapped[str | None] = mapped_column(String(64), index=True)
    asn: Mapped[str | None] = mapped_column(String(64), index=True)
    provider: Mapped[str | None] = mapped_column(Text, index=True)
    organization: Mapped[str | None] = mapped_column(Text)
    country: Mapped[str | None] = mapped_column(String(8))


class FingerprintORM(Base):
    """Persisted DOM, asset, script, and campaign fingerprints."""

    __tablename__ = "fingerprints"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    dom_hash: Mapped[str | None] = mapped_column(String(64), index=True)
    asset_hash: Mapped[str | None] = mapped_column(String(64), index=True)
    script_hash: Mapped[str | None] = mapped_column(String(64), index=True)
    campaign_fingerprint: Mapped[str | None] = mapped_column(String(64), index=True)


class MispEventORM(Base):
    """Persisted MISP event references for auditability."""

    __tablename__ = "misp_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_uuid: Mapped[str | None] = mapped_column(String(64), index=True)
    event_id: Mapped[str | None] = mapped_column(String(64), index=True)
