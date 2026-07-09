"""Builds phishing campaign payloads and MISP object structures."""

from __future__ import annotations

from phishing_intel.models.campaign import CampaignAttribution
from phishing_intel.models.findings import BrandDetectionResult, FingerprintResult, PhishingType
from phishing_intel.models.infrastructure import InfrastructureProfile, SslMetadata


class CampaignBuilder:
    """Constructs normalized phishing-campaign payload fields."""

    def build_payload(
        self,
        attribution: CampaignAttribution,
        fingerprint: FingerprintResult,
        ssl: SslMetadata | None,
        brand: BrandDetectionResult,
        phishing_type: PhishingType,
        infrastructure: InfrastructureProfile,
    ) -> dict[str, str]:
        """Build payload compatible with custom MISP object `phishing-campaign`."""

        return {
            "campaign_id": attribution.campaign_id,
            "campaign_score": str(attribution.attribution_score),
            "confidence_level": attribution.confidence_level,
            "kit_fingerprint": fingerprint.campaign_fingerprint,
            "ssl_fingerprint": ssl.sha256_fingerprint if ssl else "unknown",
            "ssl_serial": ssl.serial_number if ssl else "unknown",
            "target_brand": brand.target_brand,
            "phishing_type": phishing_type.value,
            "hosting_provider": infrastructure.provider or "unknown",
            "asn": infrastructure.asn or "unknown",
        }
