"""Infrastructure and rendering profile models.

These models normalize DNS, WHOIS/RDAP, TLS certificate, and multi-profile
rendering differences so future integrations can enrich the same stable shape.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class CertificateFinding(BaseModel):
    """Normalized TLS certificate metadata and preserved PEM evidence."""

    subject: str | None = None
    issuer: str | None = None
    serial_number: str | None = None
    san: list[str] = Field(default_factory=list)
    sha1_fingerprint: str | None = None
    sha256_fingerprint: str | None = None
    valid_from: datetime | None = None
    valid_to: datetime | None = None
    pem: str | None = None


class InfrastructureFinding(BaseModel):
    """Resolved infrastructure context for a phishing URL or domain."""

    domain: str | None = None
    ip: str | None = None
    asn: str | None = None
    organization: str | None = None
    hosting_provider: str | None = None
    country: str | None = None


class ProfileRenderResult(BaseModel):
    """Artifact hashes observed from a rendering profile."""

    profile: str
    dom_hash: str
    asset_hash: str
    script_hash: str


class MultiProfileDiff(BaseModel):
    """Differences between desktop and mobile rendering profiles."""

    base_profile: str
    compared_profile: str
    dom_changed: bool
    assets_changed: bool
    scripts_changed: bool
