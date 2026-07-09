"""Campaign attribution engine with weighted confidence scoring."""

from __future__ import annotations

from phishing_intel.models.campaign import CampaignAttribution, CorrelationMatch


class CampaignCorrelator:
    """Computes campaign attribution score based on weighted evidence."""

    def __init__(self, weights: dict[str, int] | None = None) -> None:
        self.weights = weights or {
            "fingerprint": 35,
            "certificate": 25,
            "asn": 15,
            "provider": 10,
            "brand": 15,
        }

    def attribute(
        self,
        campaign_id: str,
        fingerprint_match: bool,
        certificate_match: bool,
        asn_match: bool,
        provider_match: bool,
        brand_match: bool,
        historical_matches: list[CorrelationMatch] | None = None,
    ) -> CampaignAttribution:
        """Build final attribution output and confidence band."""

        score = 0
        if fingerprint_match:
            score += self.weights["fingerprint"]
        if certificate_match:
            score += self.weights["certificate"]
        if asn_match:
            score += self.weights["asn"]
        if provider_match:
            score += self.weights["provider"]
        if brand_match:
            score += self.weights["brand"]

        confidence = self._confidence_level(score)
        return CampaignAttribution(
            campaign_id=campaign_id,
            attribution_score=score,
            confidence_level=confidence,
            matched_campaigns=historical_matches or [],
        )

    @staticmethod
    def _confidence_level(score: int) -> str:
        """Map numeric attribution score to confidence level."""

        if score >= 70:
            return "high"
        if score >= 40:
            return "medium"
        return "low"
