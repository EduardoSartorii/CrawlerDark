"""Pydantic models for infrastructure intelligence data."""

from __future__ import annotations

from pydantic import BaseModel, Field


class DnsRecordSet(BaseModel):
    """Normalized DNS records extracted for a domain."""

    a_records: list[str] = Field(default_factory=list)
    mx_records: list[str] = Field(default_factory=list)
    ns_records: list[str] = Field(default_factory=list)


class SslMetadata(BaseModel):
    """Normalized SSL certificate metadata for correlation usage."""

    subject: str
    issuer: str
    serial_number: str
    san: list[str] = Field(default_factory=list)
    sha1_fingerprint: str
    sha256_fingerprint: str
    not_before: str
    not_after: str
    pem: str


class InfrastructureProfile(BaseModel):
    """Network and hosting information for phishing infrastructure."""

    domain: str
    ip: str | None = None
    asn: str | None = None
    organization: str | None = None
    provider: str | None = None
    country: str | None = None
    dns: DnsRecordSet | None = None
