"""Taxonomy / tag mapper.

Component responsibility
------------------------
Translate analysis + attribution results into the platform's local MISP tag
namespace. This is a *pure* function (no MISP dependency) so it is trivially
testable and reusable.

Local taxonomy
--------------
* ``fraude:marca=<brand>``            - impersonated brand.
* ``fraude:objetivo=<type>``          - phishing objective (account_takeover...).
* ``fraude:campanha=<campaign_id>``   - attributed campaign.
* ``fraude:infraestrutura=<asn>``     - hosting infrastructure (ASN/provider).
* ``fraude:criticidade=<level>``      - attribution confidence band.
* ``fraude:exfiltracao=<channel>``    - exfiltration channel(s).
"""

from __future__ import annotations

from typing import List, Optional

from phishing_intel.logging_config import get_logger
from phishing_intel.models.campaign import AttributionScore
from phishing_intel.models.findings import AnalysisResult

logger = get_logger(__name__)


class TaxonomyMapper:
    """Produce local ``fraude:*`` tags from analysis/attribution results."""

    NAMESPACE = "fraude"

    def _tag(self, predicate: str, value: str) -> str:
        """Build a single ``namespace:predicate=value`` machine tag."""

        # Normalise the value into a safe, lowercase tag token.
        safe_value = value.strip().lower().replace(" ", "_")
        return f"{self.NAMESPACE}:{predicate}={safe_value}"

    def map_tags(
        self,
        result: AnalysisResult,
        attribution: Optional[AttributionScore] = None,
    ) -> List[str]:
        """Return the full list of tags for a sample.

        Parameters
        ----------
        result:
            The analysed sample.
        attribution:
            Optional attribution score (adds campaign + criticality tags).

        Returns
        -------
        List[str]
            De-duplicated, ordered tag list.
        """

        tags: List[str] = []

        # --- Brand ----------------------------------------------------------
        if result.brand and result.brand.target_brand:
            tags.append(self._tag("marca", result.brand.target_brand))

        # --- Objective ------------------------------------------------------
        if result.classification:
            tags.append(self._tag("objetivo", result.classification.primary_type.value))

        # --- Exfiltration channels -----------------------------------------
        if result.exfiltration:
            for channel in sorted({d.channel.value for d in result.exfiltration.destinations}):
                tags.append(self._tag("exfiltracao", channel))

        # --- Infrastructure -------------------------------------------------
        if result.infrastructure:
            if result.infrastructure.asn:
                tags.append(self._tag("infraestrutura", str(result.infrastructure.asn)))
            elif result.infrastructure.hosting_provider:
                tags.append(self._tag("infraestrutura", result.infrastructure.hosting_provider))

        # --- Campaign + criticality (from attribution) ---------------------
        if attribution is not None:
            if attribution.matched_campaign_id:
                tags.append(self._tag("campanha", attribution.matched_campaign_id))
            tags.append(self._tag("criticidade", attribution.confidence.value))

        # De-duplicate while preserving order.
        seen: dict[str, None] = {}
        for tag in tags:
            seen.setdefault(tag, None)
        ordered = list(seen.keys())
        logger.info("taxonomy.mapped", count=len(ordered), tags=ordered)
        return ordered
