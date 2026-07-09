"""Typed findings emitted by static phishing analyzers.

This module is the shared schema layer for DOM, JavaScript, exfiltration,
brand, fingerprint, and campaign outputs. Pydantic models keep analyzer output
stable before it is persisted or sent to MISP.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, HttpUrl


class EvidenceArtifact(BaseModel):
    """Raw partner-supplied or collected evidence with integrity hashes."""

    url: str | None = None
    html: str | None = None
    javascript: str | None = None
    screenshot_path: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    received_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class FormFieldFinding(BaseModel):
    """Normalized HTML form field used by classifiers and exfil analysis."""

    name: str | None = None
    field_type: str | None = None
    placeholder: str | None = None
    label: str | None = None
    hidden: bool = False
    css_classes: list[str] = Field(default_factory=list)
    element_id: str | None = None


class FormFinding(BaseModel):
    """Normalized form with action, method, and extracted field metadata."""

    action: str | None = None
    method: str = "get"
    css_classes: list[str] = Field(default_factory=list)
    element_id: str | None = None
    fields: list[FormFieldFinding] = Field(default_factory=list)


class DomFinding(BaseModel):
    """Static DOM analysis output used for kit fingerprinting and MISP."""

    forms: list[FormFinding] = Field(default_factory=list)
    scripts: list[str] = Field(default_factory=list)
    links: list[str] = Field(default_factory=list)
    assets: list[str] = Field(default_factory=list)
    external_urls: list[str] = Field(default_factory=list)
    metatags: dict[str, str] = Field(default_factory=dict)
    comments: list[str] = Field(default_factory=list)
    css_classes: list[str] = Field(default_factory=list)
    html_ids: list[str] = Field(default_factory=list)
    file_names: list[str] = Field(default_factory=list)
    normalized_dom: str = ""
    dom_hash: str = ""


class JavaScriptFinding(BaseModel):
    """JavaScript indicators extracted from static source inspection."""

    fetch_urls: list[str] = Field(default_factory=list)
    xhr_urls: list[str] = Field(default_factory=list)
    axios_urls: list[str] = Field(default_factory=list)
    jquery_ajax_urls: list[str] = Field(default_factory=list)
    hardcoded_urls: list[str] = Field(default_factory=list)
    exposed_tokens: list[str] = Field(default_factory=list)
    suspicious_strings: list[str] = Field(default_factory=list)
    external_resources: list[str] = Field(default_factory=list)
    javascript_hash: str = ""


class ExfiltrationDestination(BaseModel):
    """Structured exfiltration destination with confidence and transport type."""

    destination: str
    destination_type: Literal["http", "api", "email", "messaging", "custom"]
    source: str
    confidence: int = Field(ge=0, le=100)


class ClassificationFinding(BaseModel):
    """Phishing objective classification derived from page semantics."""

    phishing_type: Literal[
        "account_takeover",
        "credential_harvesting",
        "identity_theft",
        "card_harvesting",
        "otp_harvesting",
        "generic_data_collection",
    ]
    confidence: int = Field(ge=0, le=100)
    matched_signals: list[str] = Field(default_factory=list)


class BrandFinding(BaseModel):
    """Detected target brand with the matching evidence that supported it."""

    target_brand: str | None = None
    confidence: int = Field(default=0, ge=0, le=100)
    signals: list[str] = Field(default_factory=list)


class KitFingerprintFinding(BaseModel):
    """Hashes that identify reusable phishing kit structure and assets."""

    dom_sha256: str
    asset_sha256: str
    script_sha256: str
    campaign_fingerprint: str
    directories: list[str] = Field(default_factory=list)
    file_names: list[str] = Field(default_factory=list)


class AnalysisRequest(BaseModel):
    """Input accepted by the pipeline from CTI partners or collectors."""

    url: str | None = None
    html: str | None = None
    javascript: str | None = None
    iocs: list[str] = Field(default_factory=list)
    screenshot_path: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    fetch_if_missing: bool = True


class AnalysisResult(BaseModel):
    """Complete analysis result before persistence and MISP enrichment."""

    url: str | None
    domain: str | None
    html_hash: str | None
    javascript_hash: str | None
    dom: DomFinding
    javascript: JavaScriptFinding
    classification: ClassificationFinding
    exfiltration: list[ExfiltrationDestination]
    brand: BrandFinding
    fingerprint: KitFingerprintFinding
    extracted_iocs: list[str]
    campaign_id: str
    attribution_score: int
    confidence: Literal["baixa", "media", "alta"]
    analyzed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


def coerce_url(value: str | HttpUrl | None) -> str | None:
    """Return a plain string URL for Pydantic or PyMISP callers."""

    return str(value) if value is not None else None
