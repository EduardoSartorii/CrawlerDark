"""
Infrastructure persistence models.

Pydantic models for SSL certificates, hosting infrastructure,
and network-level indicators used in correlation.

Architectural Responsibility:
    Normalizes infrastructure data from collectors for storage
    and cross-incident infrastructure correlation.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class CertificateRecord(BaseModel):
    """Normalized SSL certificate for persistence and correlation."""

    serial_number: str
    issuer: str = ""
    subject: str = ""
    sha1_fingerprint: str = ""
    sha256_fingerprint: str = ""
    san: list[str] = Field(default_factory=list)
    not_before: datetime | None = None
    not_after: datetime | None = None
    raw_pem: str = ""


class InfrastructureRecord(BaseModel):
    """Normalized hosting infrastructure record."""

    domain: str = ""
    ip: str = ""
    asn: str = ""
    organization: str = ""
    hosting_provider: str = ""
    country: str = ""
    first_seen: datetime | None = None
    last_seen: datetime | None = None


class FingerprintRecord(BaseModel):
    """Kit fingerprint record for campaign correlation."""

    dom_hash: str = ""
    asset_hash: str = ""
    script_hash: str = ""
    campaign_fingerprint: str = ""
    incident_url: str = ""
