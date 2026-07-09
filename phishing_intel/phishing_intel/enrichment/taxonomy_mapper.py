"""Local taxonomy and tagging mapper for fraud intelligence context."""

from __future__ import annotations

from phishing_intel.models.findings import ExfiltrationAnalysisResult, PhishingType


class TaxonomyMapper:
    """Builds local tags used to annotate MISP events."""

    def build_tags(
        self,
        brand: str,
        phishing_type: PhishingType,
        campaign_id: str,
        confidence: str,
        exfiltration: ExfiltrationAnalysisResult,
    ) -> list[str]:
        """Generate fraud taxonomy tags for one incident."""

        tags = [
            f"fraude:marca={brand}",
            f"fraude:objetivo={phishing_type.value}",
            f"fraude:campanha={campaign_id}",
            f"fraude:criticidade={confidence}",
        ]
        for destination in exfiltration.destinations:
            tags.append(f"fraude:exfiltracao={destination.destination_type.value}")
        return sorted(set(tags))
