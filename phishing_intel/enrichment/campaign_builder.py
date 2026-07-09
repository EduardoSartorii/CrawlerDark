"""Build MISP-ready event, attribute, and object payloads."""

from __future__ import annotations

from phishing_intel.models.findings import AnalysisResult
from phishing_intel.models.infrastructure import CertificateFinding, InfrastructureFinding


class CampaignBuilder:
    """Create a serializable phishing campaign payload before PyMISP calls."""

    def build(
        self,
        result: AnalysisResult,
        infrastructure: InfrastructureFinding | None = None,
        certificate: CertificateFinding | None = None,
        tags: list[str] | None = None,
    ) -> dict[str, object]:
        """Build MISP event data, attributes, and a custom phishing object."""

        attributes = []
        if result.url:
            attributes.append({"type": "url", "value": result.url})
        if result.domain:
            attributes.append({"type": "domain", "value": result.domain})
        if infrastructure and infrastructure.ip:
            attributes.append({"type": "ip-dst", "value": infrastructure.ip})
        if certificate and certificate.sha256_fingerprint:
            attributes.append({"type": "x509-fingerprint-sha256", "value": certificate.sha256_fingerprint})
        for ioc in result.extracted_iocs:
            attribute_type = "url" if ioc.startswith("http") else "email-src" if "@" in ioc else "text"
            attributes.append({"type": attribute_type, "value": ioc})
        phishing_object = {
            "name": "phishing-campaign",
            "attributes": {
                "campaign_id": result.campaign_id,
                "campaign_score": str(result.attribution_score),
                "confidence_level": result.confidence,
                "kit_fingerprint": result.fingerprint.campaign_fingerprint,
                "ssl_fingerprint": certificate.sha256_fingerprint if certificate else None,
                "ssl_serial": certificate.serial_number if certificate else None,
                "target_brand": result.brand.target_brand,
                "phishing_type": result.classification.phishing_type,
                "hosting_provider": infrastructure.hosting_provider if infrastructure else None,
                "asn": infrastructure.asn if infrastructure else None,
            },
        }
        return {
            "info": f"Phishing campaign {result.campaign_id}",
            "distribution": 0,
            "threat_level_id": 2,
            "analysis": 2,
            "tags": tags or [],
            "attributes": attributes,
            "objects": [phishing_object],
        }
