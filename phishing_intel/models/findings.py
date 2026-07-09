"""
Pydantic domain models for phishing analysis findings.

Defines structured data transfer objects used across the analysis pipeline.
These models represent intermediate and final analysis results before
persistence to the database or export to MISP.

Architectural Responsibility:
    Type-safe contracts between collectors, analyzers, correlators, and
    enrichment modules. Ensures consistent data shapes throughout the pipeline.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class PhishingType(str, Enum):
    """Classification of phishing campaign objectives."""

    ACCOUNT_TAKEOVER = "account_takeover"
    CREDENTIAL_HARVESTING = "credential_harvesting"
    IDENTITY_THEFT = "identity_theft"
    CARD_HARVESTING = "card_harvesting"
    OTP_HARVESTING = "otp_harvesting"
    GENERIC_DATA_COLLECTION = "generic_data_collection"


class ConfidenceLevel(str, Enum):
    """Attribution confidence classification."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ExfiltrationType(str, Enum):
    """Classification of data exfiltration methods."""

    HTTP = "http"
    API = "api"
    EMAIL = "email"
    MESSAGING = "messaging"
    CUSTOM = "custom"


class RenderProfile(str, Enum):
    """Browser render profiles for multi-profile analysis."""

    DESKTOP_CHROME = "desktop_chrome"
    DESKTOP_EDGE = "desktop_edge"
    DESKTOP_FIREFOX = "desktop_firefox"
    ANDROID_CHROME = "android_chrome"
    IPHONE_SAFARI = "iphone_safari"


class FormField(BaseModel):
    """Single HTML form input field."""

    name: str = ""
    field_type: str = "text"
    id: str = ""
    placeholder: str = ""
    label: str = ""
    css_class: str = ""
    is_hidden: bool = False
    autocomplete: str = ""


class FormFinding(BaseModel):
    """Extracted HTML form structure."""

    action: str = ""
    method: str = "GET"
    fields: list[FormField] = Field(default_factory=list)
    css_classes: list[str] = Field(default_factory=list)
    html_ids: list[str] = Field(default_factory=list)


class ScriptFinding(BaseModel):
    """Extracted script reference from DOM."""

    src: str = ""
    inline: bool = False
    content_hash: str = ""
    content_preview: str = ""


class LinkFinding(BaseModel):
    """Extracted hyperlink from DOM."""

    href: str
    text: str = ""
    rel: str = ""


class AssetFinding(BaseModel):
    """External asset reference (images, stylesheets, etc.)."""

    url: str
    asset_type: str
    filename: str = ""


class DOMFinding(BaseModel):
    """
    Complete DOM analysis result.

    Contains normalized DOM structure, structural hash, and all
    extracted elements for correlation and kit fingerprinting.
    """

    forms: list[FormFinding] = Field(default_factory=list)
    scripts: list[ScriptFinding] = Field(default_factory=list)
    links: list[LinkFinding] = Field(default_factory=list)
    assets: list[AssetFinding] = Field(default_factory=list)
    external_urls: list[str] = Field(default_factory=list)
    metatags: dict[str, str] = Field(default_factory=dict)
    html_comments: list[str] = Field(default_factory=list)
    css_classes: list[str] = Field(default_factory=list)
    html_ids: list[str] = Field(default_factory=list)
    filenames: list[str] = Field(default_factory=list)
    normalized_dom: str = ""
    structural_hash: str = ""


class JavaScriptFinding(BaseModel):
    """JavaScript static analysis result."""

    fetch_calls: list[str] = Field(default_factory=list)
    xhr_urls: list[str] = Field(default_factory=list)
    ajax_urls: list[str] = Field(default_factory=list)
    axios_urls: list[str] = Field(default_factory=list)
    hardcoded_urls: list[str] = Field(default_factory=list)
    exposed_tokens: list[str] = Field(default_factory=list)
    exposed_keys: list[str] = Field(default_factory=list)
    suspicious_strings: list[str] = Field(default_factory=list)
    external_resources: list[str] = Field(default_factory=list)
    script_hash: str = ""


class ExfiltrationDestination(BaseModel):
    """Identified data exfiltration endpoint."""

    url: str
    method: str = "POST"
    exfiltration_type: ExfiltrationType = ExfiltrationType.HTTP
    confidence: float = Field(ge=0.0, le=100.0, default=50.0)
    source: str = ""  # form, fetch, xhr, etc.


class ExfiltrationFinding(BaseModel):
    """Aggregated exfiltration analysis."""

    destinations: list[ExfiltrationDestination] = Field(default_factory=list)
    primary_method: ExfiltrationType | None = None
    overall_confidence: float = 0.0


class KitFingerprint(BaseModel):
    """
    Phishing kit fingerprint for campaign correlation.

    Composite hash derived from DOM structure, assets, and scripts
    to identify reused phishing kit deployments.
    """

    dom_hash: str = ""
    asset_hash: str = ""
    script_hash: str = ""
    campaign_fingerprint: str = ""
    directory_structure: list[str] = Field(default_factory=list)
    file_naming_patterns: list[str] = Field(default_factory=list)


class BrandFinding(BaseModel):
    """Detected target brand impersonation."""

    brand: str
    confidence: float = Field(ge=0.0, le=100.0)
    detection_sources: list[str] = Field(default_factory=list)


class SSLCertificate(BaseModel):
    """Parsed SSL/TLS certificate metadata."""

    subject: str = ""
    issuer: str = ""
    serial_number: str = ""
    san: list[str] = Field(default_factory=list)
    sha1_fingerprint: str = ""
    sha256_fingerprint: str = ""
    not_before: datetime | None = None
    not_after: datetime | None = None
    raw_certificate: str = ""


class InfrastructureFinding(BaseModel):
    """Hosting infrastructure metadata."""

    domain: str = ""
    ip: str = ""
    asn: str = ""
    organization: str = ""
    hosting_provider: str = ""
    country: str = ""


class IOCFinding(BaseModel):
    """Extracted Indicators of Compromise."""

    domains: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)
    ips: list[str] = Field(default_factory=list)
    emails: list[str] = Field(default_factory=list)
    hashes: list[str] = Field(default_factory=list)


class ProfileDiff(BaseModel):
    """Diff between render profile analyses."""

    profile_a: RenderProfile
    profile_b: RenderProfile
    dom_diff: list[str] = Field(default_factory=list)
    asset_diff: list[str] = Field(default_factory=list)
    script_diff: list[str] = Field(default_factory=list)


class AnalysisResult(BaseModel):
    """
    Complete analysis result for a single phishing incident.

    Aggregates all analyzer outputs into a unified finding suitable
    for correlation, persistence, and MISP enrichment.
    """

    url: str
    html_hash: str = ""
    javascript_hash: str = ""
    dom: DOMFinding = Field(default_factory=DOMFinding)
    javascript: JavaScriptFinding = Field(default_factory=JavaScriptFinding)
    phishing_type: PhishingType = PhishingType.GENERIC_DATA_COLLECTION
    exfiltration: ExfiltrationFinding = Field(default_factory=ExfiltrationFinding)
    kit_fingerprint: KitFingerprint = Field(default_factory=KitFingerprint)
    brand: BrandFinding | None = None
    ssl: SSLCertificate | None = None
    infrastructure: InfrastructureFinding | None = None
    iocs: IOCFinding = Field(default_factory=IOCFinding)
    profile_diffs: list[ProfileDiff] = Field(default_factory=list)
    render_profiles: dict[str, str] = Field(default_factory=dict)
    analyzed_at: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
