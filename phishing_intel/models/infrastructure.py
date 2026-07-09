"""Infrastructure-related Pydantic domain models.

Responsibility
--------------
Describe, in a transport-agnostic way, the network/PKI facts collected about a
phishing site: the TLS certificate, DNS records and hosting infrastructure
(IP/ASN/provider/country). These models are produced by the ``collectors``
layer and consumed by the ``correlators`` and ``enrichment`` layers.
"""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field


class CertificateInfo(BaseModel):
    """Normalised representation of an X.509 TLS certificate.

    Captures the fields required for both MISP ``x509`` objects and campaign
    correlation (a reused certificate is a strong attribution signal).
    """

    subject: Optional[str] = None
    issuer: Optional[str] = None
    serial_number: Optional[str] = None
    # Subject Alternative Names (DNS entries) - useful for pivoting.
    san: List[str] = Field(default_factory=list)
    sha1_fingerprint: Optional[str] = None
    sha256_fingerprint: Optional[str] = None
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    # Raw PEM preserved for the evidence chain.
    raw_pem: Optional[str] = None


class DNSRecords(BaseModel):
    """DNS resolution results for the phishing domain."""

    domain: Optional[str] = None
    a: List[str] = Field(default_factory=list)
    aaaa: List[str] = Field(default_factory=list)
    mx: List[str] = Field(default_factory=list)
    ns: List[str] = Field(default_factory=list)
    txt: List[str] = Field(default_factory=list)
    cname: List[str] = Field(default_factory=list)


class InfrastructureInfo(BaseModel):
    """Hosting infrastructure facts for a phishing site.

    The structure is deliberately shaped to be trivially enriched later by
    external providers (Passive DNS, SecurityTrails, RiskIQ, WhoisXML, Shodan,
    CIRCL) without changing the schema.
    """

    domain: Optional[str] = None
    ip: Optional[str] = None
    asn: Optional[str] = None
    asn_description: Optional[str] = None
    organization: Optional[str] = None
    hosting_provider: Optional[str] = None
    country: Optional[str] = None
    # DNS records attached here for a single infrastructure snapshot.
    dns: Optional[DNSRecords] = None
