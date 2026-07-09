"""Analysis "findings" Pydantic domain models.

Responsibility
--------------
Define every artifact produced by the ``analyzers`` layer plus the input
``PhishingSample`` accepted by the platform and the aggregate
``AnalysisResult`` that stitches all findings together.

These models are the *lingua franca* of the platform: analyzers emit them,
correlators read them, repositories persist them and the MISP enrichment layer
maps them to events/objects.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, Field

from phishing_intel.models.infrastructure import (
    CertificateInfo,
    InfrastructureInfo,
)


class PhishingType(str, Enum):
    """Canonical phishing objective classification labels."""

    ACCOUNT_TAKEOVER = "account_takeover"
    CREDENTIAL_HARVESTING = "credential_harvesting"
    IDENTITY_THEFT = "identity_theft"
    CARD_HARVESTING = "card_harvesting"
    OTP_HARVESTING = "otp_harvesting"
    GENERIC_DATA_COLLECTION = "generic_data_collection"


class ExfiltrationChannel(str, Enum):
    """Transport used to exfiltrate harvested victim data."""

    HTTP = "http"
    API = "api"
    EMAIL = "email"
    MESSAGING = "messaging"
    CUSTOM = "custom"


class ConfidenceLevel(str, Enum):
    """Human-readable confidence bands for attribution scores."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


# ---------------------------------------------------------------------------
# Input model
# ---------------------------------------------------------------------------
class PhishingSample(BaseModel):
    """A unit of work submitted to the platform.

    Reflects the operational reality that partners usually already provide the
    HTML/JavaScript. ``html`` and ``javascript`` are therefore optional; when
    ``html`` is missing the secondary collection flow fetches it.
    """

    url: str
    html: Optional[str] = None
    # Additional JavaScript files provided out-of-band (beyond inline <script>).
    javascript: List[str] = Field(default_factory=list)
    screenshots: List[str] = Field(default_factory=list)
    # Free-form detection metadata supplied by the partner.
    metadata: Dict[str, str] = Field(default_factory=dict)
    received_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


# ---------------------------------------------------------------------------
# DOM analysis
# ---------------------------------------------------------------------------
class FormField(BaseModel):
    """A single ``<input>``/``<select>``/``<textarea>`` element of a form."""

    tag: str = "input"
    type: Optional[str] = None
    name: Optional[str] = None
    id: Optional[str] = None
    placeholder: Optional[str] = None
    label: Optional[str] = None
    hidden: bool = False
    value: Optional[str] = None


class FormInfo(BaseModel):
    """A normalised ``<form>`` element."""

    action: Optional[str] = None
    method: str = "get"
    id: Optional[str] = None
    css_classes: List[str] = Field(default_factory=list)
    fields: List[FormField] = Field(default_factory=list)


class DOMAnalysis(BaseModel):
    """Structured output of the DOM analyzer."""

    forms: List[FormInfo] = Field(default_factory=list)
    hidden_fields: List[FormField] = Field(default_factory=list)
    scripts_inline: List[str] = Field(default_factory=list)
    scripts_external: List[str] = Field(default_factory=list)
    links: List[str] = Field(default_factory=list)
    assets: List[str] = Field(default_factory=list)
    external_urls: List[str] = Field(default_factory=list)
    meta_tags: Dict[str, str] = Field(default_factory=dict)
    comments: List[str] = Field(default_factory=list)
    css_classes: List[str] = Field(default_factory=list)
    html_ids: List[str] = Field(default_factory=list)
    filenames: List[str] = Field(default_factory=list)
    title: Optional[str] = None
    # Normalised skeleton of the DOM (tag sequence) used for structural hashing.
    normalized_dom: str = ""
    # SHA256 of ``normalized_dom`` - the page's structural fingerprint.
    structural_hash: Optional[str] = None


# ---------------------------------------------------------------------------
# Phishing classification
# ---------------------------------------------------------------------------
class PhishingClassification(BaseModel):
    """Result of classifying the phishing objective(s)."""

    primary_type: PhishingType = PhishingType.GENERIC_DATA_COLLECTION
    # All detected types with their individual confidence (0-100).
    detected_types: Dict[PhishingType, int] = Field(default_factory=dict)
    # Human-readable reasons that triggered each detection.
    signals: List[str] = Field(default_factory=list)
    confidence: int = 0


# ---------------------------------------------------------------------------
# JavaScript analysis
# ---------------------------------------------------------------------------
class JavaScriptAnalysis(BaseModel):
    """Structured output of the JavaScript analyzer."""

    fetch_calls: List[str] = Field(default_factory=list)
    xhr_calls: List[str] = Field(default_factory=list)
    axios_calls: List[str] = Field(default_factory=list)
    jquery_ajax_calls: List[str] = Field(default_factory=list)
    hardcoded_urls: List[str] = Field(default_factory=list)
    exposed_tokens: List[str] = Field(default_factory=list)
    exposed_keys: List[str] = Field(default_factory=list)
    suspicious_strings: List[str] = Field(default_factory=list)
    external_resources: List[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Exfiltration analysis
# ---------------------------------------------------------------------------
class ExfiltrationDestination(BaseModel):
    """A single detected exfiltration endpoint."""

    destination: str
    channel: ExfiltrationChannel = ExfiltrationChannel.HTTP
    # Where the signal came from (e.g. "form.action", "js.fetch").
    source: str = "unknown"
    confidence: int = 50


class ExfiltrationAnalysis(BaseModel):
    """Aggregated exfiltration findings."""

    destinations: List[ExfiltrationDestination] = Field(default_factory=list)
    # Overall confidence that exfiltration was detected at all (0-100).
    confidence: int = 0


# ---------------------------------------------------------------------------
# Kit fingerprinting
# ---------------------------------------------------------------------------
class KitFingerprint(BaseModel):
    """Fingerprint used to correlate phishing kits across incidents."""

    dom_hash: Optional[str] = None
    asset_hash: Optional[str] = None
    script_hash: Optional[str] = None
    # Directory-structure / path signature of the kit.
    path_signature: List[str] = Field(default_factory=list)
    # The composite fingerprint that identifies a reused kit / campaign.
    campaign_fingerprint: Optional[str] = None


# ---------------------------------------------------------------------------
# Brand detection
# ---------------------------------------------------------------------------
class BrandDetection(BaseModel):
    """Detected impersonated brand / target."""

    target_brand: Optional[str] = None
    category: Optional[str] = None
    confidence: int = 0
    # Every brand considered, with its score, for transparency.
    candidates: Dict[str, int] = Field(default_factory=dict)
    signals: List[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Multi-profile rendering comparison
# ---------------------------------------------------------------------------
class RenderProfileResult(BaseModel):
    """DOM/asset/script hashes captured for a single render profile."""

    profile: str
    dom_hash: Optional[str] = None
    asset_hash: Optional[str] = None
    script_hash: Optional[str] = None


class RenderDiff(BaseModel):
    """Difference between two render profiles (e.g. desktop vs mobile)."""

    profile_a: str
    profile_b: str
    dom_differs: bool = False
    assets_only_in_a: List[str] = Field(default_factory=list)
    assets_only_in_b: List[str] = Field(default_factory=list)
    scripts_only_in_a: List[str] = Field(default_factory=list)
    scripts_only_in_b: List[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Aggregate result
# ---------------------------------------------------------------------------
class AnalysisResult(BaseModel):
    """The complete analysis of a single phishing sample.

    This is the object persisted to the database, fed to the correlation engine
    and mapped into a MISP event. It is the canonical "record" of an incident.
    """

    url: str
    domain: Optional[str] = None
    html_hash: Optional[str] = None
    javascript_hash: Optional[str] = None
    analyzed_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    dom: Optional[DOMAnalysis] = None
    classification: Optional[PhishingClassification] = None
    javascript: Optional[JavaScriptAnalysis] = None
    exfiltration: Optional[ExfiltrationAnalysis] = None
    fingerprint: Optional[KitFingerprint] = None
    brand: Optional[BrandDetection] = None
    certificate: Optional[CertificateInfo] = None
    infrastructure: Optional[InfrastructureInfo] = None
    render_diffs: List[RenderDiff] = Field(default_factory=list)

    # Flat list of IOCs extracted across every analyzer (deduplicated).
    iocs: List[str] = Field(default_factory=list)
