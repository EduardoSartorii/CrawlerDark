"""Pydantic domain models shared across the platform.

These models form the stable contract between layers. Re-exported here for
ergonomic imports (``from phishing_intel.models import AnalysisResult``).
"""

from phishing_intel.models.campaign import (
    AttributionScore,
    Campaign,
    CampaignMatch,
)
from phishing_intel.models.findings import (
    AnalysisResult,
    BrandDetection,
    ConfidenceLevel,
    DOMAnalysis,
    ExfiltrationAnalysis,
    ExfiltrationChannel,
    ExfiltrationDestination,
    FormField,
    FormInfo,
    JavaScriptAnalysis,
    KitFingerprint,
    PhishingClassification,
    PhishingSample,
    PhishingType,
    RenderDiff,
    RenderProfileResult,
)
from phishing_intel.models.infrastructure import (
    CertificateInfo,
    DNSRecords,
    InfrastructureInfo,
)

__all__ = [
    "AnalysisResult",
    "AttributionScore",
    "BrandDetection",
    "Campaign",
    "CampaignMatch",
    "CertificateInfo",
    "ConfidenceLevel",
    "DNSRecords",
    "DOMAnalysis",
    "ExfiltrationAnalysis",
    "ExfiltrationChannel",
    "ExfiltrationDestination",
    "FormField",
    "FormInfo",
    "InfrastructureInfo",
    "JavaScriptAnalysis",
    "KitFingerprint",
    "PhishingClassification",
    "PhishingSample",
    "PhishingType",
    "RenderDiff",
    "RenderProfileResult",
]
