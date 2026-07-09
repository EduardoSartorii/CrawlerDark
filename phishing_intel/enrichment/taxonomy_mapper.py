"""
MISP taxonomy and local tag mapper.

Maps analysis results to MISP taxonomies and local fraude:* tags
for consistent threat intelligence classification.

Architectural Responsibility:
    Tag generation layer ensuring consistent taxonomy application
    across all MISP exports and local campaign records.

Local Tags:
    fraude:marca=<brand>
    fraude:objetivo=<phishing_type>
    fraude:campanha=<campaign_id>
    fraude:infraestrutura=<provider>
    fraude:criticidade=<level>
    fraude:exfiltracao=<method>
"""

from __future__ import annotations

import structlog

from phishing_intel.models.campaign import CampaignAttribution
from phishing_intel.models.findings import AnalysisResult, ConfidenceLevel

logger = structlog.get_logger(__name__)


class TaxonomyMapper:
    """
    Taxonomy and tag mapping for MISP export.

    Generates both MISP-standard and local fraude:* tags
    from analysis and attribution results.
    """

    def map_tags(
        self,
        result: AnalysisResult,
        attribution: CampaignAttribution,
    ) -> list[str]:
        """
        Generate complete tag set for MISP event.

        Args:
            result: Analysis result.
            attribution: Campaign attribution.

        Returns:
            List of MISP-compatible tag strings.
        """
        tags: list[str] = []

        # MISP standard tags
        tags.append("misp-galaxy:threat-actor=\"Phishing\"")
        tags.append(f"type:phishing=\"{result.phishing_type.value}\"")

        # Local fraude:* tags
        if result.brand:
            tags.append(f"fraude:marca={result.brand.brand}")

        tags.append(f"fraude:objetivo={result.phishing_type.value}")
        tags.append(f"fraude:campanha={attribution.campaign_id}")

        if result.infrastructure and result.infrastructure.hosting_provider:
            provider = result.infrastructure.hosting_provider.replace(" ", "_").lower()
            tags.append(f"fraude:infraestrutura={provider}")

        tags.append(f"fraude:criticidade={self._map_criticality(attribution.confidence)}")

        if result.exfiltration.primary_method:
            tags.append(f"fraude:exfiltracao={result.exfiltration.primary_method.value}")

        logger.info("taxonomy_mapped", tag_count=len(tags))
        return tags

    def _map_criticality(self, confidence: ConfidenceLevel) -> str:
        """Map confidence level to criticality tag."""
        mapping = {
            ConfidenceLevel.LOW: "baixa",
            ConfidenceLevel.MEDIUM: "media",
            ConfidenceLevel.HIGH: "alta",
        }
        return mapping.get(confidence, "baixa")

    def map_misp_galaxy_tags(self, result: AnalysisResult) -> list[str]:
        """
        Generate MISP galaxy tags for brand sector.

        Args:
            result: Analysis result with brand detection.

        Returns:
            Galaxy tag strings.
        """
        tags: list[str] = []
        if result.brand:
            tags.append(f"misp-galaxy:target=\"{result.brand.brand}\"")
        return tags
