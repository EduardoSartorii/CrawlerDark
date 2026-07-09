"""Campaign builder.

Component responsibility
------------------------
Assemble a :class:`~phishing_intel.models.campaign.Campaign` domain object from
an :class:`~phishing_intel.models.findings.AnalysisResult` and its
:class:`~phishing_intel.models.campaign.AttributionScore`. This bridges the
correlation output and the persistence/enrichment layers.

Execution flow
--------------
``CampaignBuilder.build(result, attribution)`` -> derive campaign id ->
populate brand/type/fingerprint/score/confidence -> return ``Campaign``.
"""

from __future__ import annotations

from phishing_intel.logging_config import get_logger
from phishing_intel.models.campaign import AttributionScore, Campaign
from phishing_intel.models.findings import AnalysisResult, ConfidenceLevel

logger = get_logger(__name__)


class CampaignBuilder:
    """Build :class:`Campaign` objects from analysis + attribution results."""

    def build(
        self,
        result: AnalysisResult,
        attribution: AttributionScore,
    ) -> Campaign:
        """Construct a campaign object for a sample.

        Business rule: the campaign id comes from the attribution result when
        available (existing or proposed); otherwise a deterministic fallback id
        is derived from the kit fingerprint so identical kits still cluster.
        """

        campaign_id = attribution.matched_campaign_id
        if campaign_id is None:
            fingerprint = (
                result.fingerprint.campaign_fingerprint
                if result.fingerprint
                else None
            )
            brand = result.brand.target_brand if result.brand else "unknown"
            campaign_id = (
                f"CAMP-{brand}-{fingerprint[:12]}"
                if fingerprint
                else f"CAMP-{brand}-adhoc"
            )

        campaign = Campaign(
            campaign_id=campaign_id,
            target_brand=result.brand.target_brand if result.brand else None,
            phishing_type=(
                result.classification.primary_type.value
                if result.classification
                else None
            ),
            kit_fingerprint=(
                result.fingerprint.campaign_fingerprint if result.fingerprint else None
            ),
            score=attribution.score,
            confidence=attribution.confidence or ConfidenceLevel.LOW,
            members=[result.url],
        )
        logger.info(
            "campaign.built",
            campaign_id=campaign.campaign_id,
            score=campaign.score,
            confidence=campaign.confidence.value,
        )
        return campaign
