"""SQLAlchemy ORM models (persistence schema).

Responsibility
--------------
Define the relational schema used to persist the historical record of
campaigns, phishing sites, certificates, infrastructure, kit fingerprints and
MISP events. This history is what powers the correlation engine over time.

Execution flow
--------------
``Base.metadata.create_all(engine)`` (called by ``session.init_db``) creates
these tables. Repositories in :mod:`phishing_intel.database.repositories`
perform all reads/writes; application code never touches the ORM directly.

Schema notes
------------
The columns intentionally mirror the delivery specification's table list
(campaigns, phishing_sites, certificates, infrastructures, fingerprints,
misp_events) while adding a handful of foreign keys + JSON payload columns so
the full :class:`~phishing_intel.models.findings.AnalysisResult` can be
round-tripped.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    relationship,
)


class Base(DeclarativeBase):
    """Declarative base for every ORM model."""


def _utcnow() -> datetime:
    """Timezone-aware UTC now (used as column default)."""

    return datetime.now(timezone.utc)


class Campaign(Base):
    """A tracked phishing campaign."""

    __tablename__ = "campaigns"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    campaign_id: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    target_brand: Mapped[str | None] = mapped_column(String(128), nullable=True)
    phishing_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    kit_fingerprint: Mapped[str | None] = mapped_column(String(128), nullable=True)
    score: Mapped[int] = mapped_column(Integer, default=0)
    confidence: Mapped[str] = mapped_column(String(16), default="low")
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)

    sites: Mapped[list["PhishingSite"]] = relationship(
        back_populates="campaign", cascade="all, delete-orphan"
    )


class PhishingSite(Base):
    """A single analysed phishing URL/site."""

    __tablename__ = "phishing_sites"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    url: Mapped[str] = mapped_column(Text)
    domain: Mapped[str | None] = mapped_column(String(255), index=True, nullable=True)
    html_hash: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    javascript_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    target_brand: Mapped[str | None] = mapped_column(String(128), nullable=True)
    phishing_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Full AnalysisResult serialised as JSON for lossless round-tripping.
    result_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)

    campaign_id: Mapped[int | None] = mapped_column(
        ForeignKey("campaigns.id"), nullable=True
    )
    campaign: Mapped["Campaign | None"] = relationship(back_populates="sites")

    fingerprint: Mapped["Fingerprint | None"] = relationship(
        back_populates="site", cascade="all, delete-orphan", uselist=False
    )
    certificate: Mapped["Certificate | None"] = relationship(
        back_populates="site", cascade="all, delete-orphan", uselist=False
    )
    infrastructure: Mapped["Infrastructure | None"] = relationship(
        back_populates="site", cascade="all, delete-orphan", uselist=False
    )


class Certificate(Base):
    """A TLS certificate observed for a phishing site."""

    __tablename__ = "certificates"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    serial_number: Mapped[str | None] = mapped_column(String(128), index=True, nullable=True)
    issuer: Mapped[str | None] = mapped_column(Text, nullable=True)
    subject: Mapped[str | None] = mapped_column(Text, nullable=True)
    fingerprint: Mapped[str | None] = mapped_column(String(128), index=True, nullable=True)
    site_id: Mapped[int | None] = mapped_column(
        ForeignKey("phishing_sites.id"), nullable=True
    )
    site: Mapped["PhishingSite | None"] = relationship(back_populates="certificate")


class Infrastructure(Base):
    """Hosting infrastructure facts for a phishing site."""

    __tablename__ = "infrastructures"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ip: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    asn: Mapped[str | None] = mapped_column(String(32), index=True, nullable=True)
    provider: Mapped[str | None] = mapped_column(String(255), nullable=True)
    country: Mapped[str | None] = mapped_column(String(8), nullable=True)
    site_id: Mapped[int | None] = mapped_column(
        ForeignKey("phishing_sites.id"), nullable=True
    )
    site: Mapped["PhishingSite | None"] = relationship(back_populates="infrastructure")


class Fingerprint(Base):
    """Kit fingerprint hashes for a phishing site."""

    __tablename__ = "fingerprints"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    dom_hash: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    asset_hash: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    script_hash: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    campaign_fingerprint: Mapped[str | None] = mapped_column(
        String(64), index=True, nullable=True
    )
    site_id: Mapped[int | None] = mapped_column(
        ForeignKey("phishing_sites.id"), nullable=True
    )
    site: Mapped["PhishingSite | None"] = relationship(back_populates="fingerprint")


class MispEvent(Base):
    """A MISP event created/linked for a phishing site."""

    __tablename__ = "misp_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_uuid: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    event_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    url: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
