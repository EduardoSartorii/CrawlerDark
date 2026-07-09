"""Pydantic models for analyzer outputs and evidence artifacts."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field, HttpUrl


class PhishingType(str, Enum):
    """Supported phishing objectives detected by the classifier."""

    ACCOUNT_TAKEOVER = "account_takeover"
    CREDENTIAL_HARVESTING = "credential_harvesting"
    IDENTITY_THEFT = "identity_theft"
    CARD_HARVESTING = "card_harvesting"
    OTP_HARVESTING = "otp_harvesting"
    GENERIC_DATA_COLLECTION = "generic_data_collection"


class ExfiltrationType(str, Enum):
    """Supported exfiltration channel types."""

    HTTP = "http"
    API = "api"
    EMAIL = "email"
    MESSAGING = "messaging"
    CUSTOM = "custom"


class DomForm(BaseModel):
    """Structured representation of a HTML form."""

    action: str | None = None
    method: str | None = None
    input_names: list[str] = Field(default_factory=list)
    hidden_fields: list[str] = Field(default_factory=list)
    css_classes: list[str] = Field(default_factory=list)
    element_id: str | None = None


class DomAnalysisResult(BaseModel):
    """Results extracted from static DOM parsing."""

    forms: list[DomForm] = Field(default_factory=list)
    scripts: list[str] = Field(default_factory=list)
    links: list[str] = Field(default_factory=list)
    assets: list[str] = Field(default_factory=list)
    external_urls: list[str] = Field(default_factory=list)
    metatags: dict[str, str] = Field(default_factory=dict)
    comments: list[str] = Field(default_factory=list)
    normalized_dom: str
    dom_hash: str


class JavaScriptAnalysisResult(BaseModel):
    """Findings extracted from JavaScript code."""

    fetch_targets: list[str] = Field(default_factory=list)
    xhr_targets: list[str] = Field(default_factory=list)
    axios_targets: list[str] = Field(default_factory=list)
    jquery_ajax_targets: list[str] = Field(default_factory=list)
    hardcoded_urls: list[str] = Field(default_factory=list)
    exposed_tokens: list[str] = Field(default_factory=list)
    exposed_keys: list[str] = Field(default_factory=list)
    suspicious_strings: list[str] = Field(default_factory=list)
    script_hashes: list[str] = Field(default_factory=list)


class ExfiltrationDestination(BaseModel):
    """Normalized exfiltration endpoint with confidence score."""

    target: str
    destination_type: ExfiltrationType
    confidence: float = Field(ge=0.0, le=1.0)


class ExfiltrationAnalysisResult(BaseModel):
    """Structured output from exfiltration analyzer."""

    destinations: list[ExfiltrationDestination] = Field(default_factory=list)
    score: float = Field(default=0.0, ge=0.0, le=1.0)


class FingerprintResult(BaseModel):
    """Computed fingerprint hashes for kit and campaign correlation."""

    dom_hash: str
    asset_hash: str
    script_hash: str
    campaign_fingerprint: str


class BrandDetectionResult(BaseModel):
    """Detected target brand and confidence level."""

    target_brand: str
    confidence: float = Field(ge=0.0, le=1.0)


class EvidenceRecord(BaseModel):
    """Chain-of-custody evidence record for one analyzed incident."""

    timestamp: datetime = Field(default_factory=lambda: datetime.now(tz=timezone.utc))
    url: HttpUrl | None = None
    html_hash: str | None = None
    javascript_hash: str | None = None
    ssl_fingerprint: str | None = None
    analysis_summary: dict[str, str | int | float | list[str]] = Field(default_factory=dict)
