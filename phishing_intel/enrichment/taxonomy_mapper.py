"""Local fraud taxonomy mapper for MISP tags."""

from __future__ import annotations

from phishing_intel.models.findings import AnalysisResult


class TaxonomyMapper:
    """Map analysis findings to local MISP fraud tags."""

    def tags_for(self, result: AnalysisResult) -> list[str]:
        """Return local taxonomy tags for an analysis result."""

        tags = [
            f"fraude:objetivo={result.classification.phishing_type}",
            f"fraude:campanha={result.campaign_id}",
            f"fraude:criticidade={result.confidence}",
        ]
        if result.brand.target_brand:
            tags.append(f"fraude:marca={result.brand.target_brand}")
        if result.exfiltration:
            tags.append(f"fraude:exfiltracao={result.exfiltration[0].destination_type}")
        if result.domain:
            tags.append(f"fraude:infraestrutura={result.domain}")
        return tags
