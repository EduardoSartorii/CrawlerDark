"""Campaign correlation engine with weighted attribution scoring."""

from __future__ import annotations

from phishing_intel.models.campaign import CampaignAttribution, CampaignSignal, confidence_from_score
from phishing_intel.models.findings import BrandFinding, DomFinding, JavaScriptFinding, KitFingerprintFinding
from phishing_intel.models.infrastructure import CertificateFinding, InfrastructureFinding
from phishing_intel.utils import sha256_text


class CampaignCorrelator:
    """Calculate campaign IDs and attribution scores from CTI signals."""

    WEIGHTS = {
        "same_fingerprint": 45,
        "same_certificate": 30,
        "same_asn": 12,
        "same_provider": 12,
        "same_dom_pattern": 20,
        "same_javascript_pattern": 15,
        "same_brand": 15,
    }

    def correlate(
        self,
        fingerprint: KitFingerprintFinding,
        dom: DomFinding,
        javascript: JavaScriptFinding,
        brand: BrandFinding,
        infrastructure: InfrastructureFinding | None = None,
        certificate: CertificateFinding | None = None,
        historical: list[dict[str, str | None]] | None = None,
    ) -> CampaignAttribution:
        """Return an attribution decision for the current phishing incident."""

        signals: list[CampaignSignal] = []
        historical = historical or []
        if any(row.get("campaign_fingerprint") == fingerprint.campaign_fingerprint for row in historical):
            signals.append(self._signal("same_fingerprint", fingerprint.campaign_fingerprint))
        if any(row.get("dom_hash") == fingerprint.dom_sha256 for row in historical):
            signals.append(self._signal("same_dom_pattern", fingerprint.dom_sha256))
        if any(row.get("script_hash") == fingerprint.script_sha256 for row in historical):
            signals.append(self._signal("same_javascript_pattern", fingerprint.script_sha256))
        if certificate and certificate.sha256_fingerprint:
            signals.append(self._signal("same_certificate", certificate.sha256_fingerprint))
        if infrastructure and infrastructure.asn:
            signals.append(self._signal("same_asn", infrastructure.asn))
        if infrastructure and infrastructure.hosting_provider:
            signals.append(self._signal("same_provider", infrastructure.hosting_provider))
        if brand.target_brand:
            signals.append(self._signal("same_brand", brand.target_brand))
        score = min(100, sum(signal.weight for signal in signals))
        campaign_id = "phish-" + sha256_text(
            "|".join([fingerprint.campaign_fingerprint, brand.target_brand or "", dom.dom_hash, javascript.javascript_hash])
        )[:16]
        return CampaignAttribution(
            campaign_id=campaign_id,
            score=score,
            confidence=confidence_from_score(score),
            signals=signals,
        )

    def _signal(self, name: str, value: str) -> CampaignSignal:
        """Create a weighted signal from a known correlation name."""

        return CampaignSignal(name=name, value=value, weight=self.WEIGHTS[name])
