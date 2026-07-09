"""Campaign correlation engine (attribution scoring).

Component responsibility
------------------------
Fuse every correlation signal (kit fingerprint, DOM/JS structure, certificate,
ASN, provider, brand) into a single weighted **attribution score** (0-100),
classify its confidence band and decide which campaign a sample belongs to.

Scoring model
-------------
``score = min(100, sum(weight of each fired signal))``

Confidence bands (from ``config.correlation.thresholds``):
* ``0-39``   -> low confidence
* ``40-69``  -> medium confidence
* ``70-100`` -> high confidence

Campaign attribution
--------------------
* If any correlated historical site already belongs to a campaign, the new
  sample inherits that campaign id (campaigns grow over time).
* Otherwise, when confidence is at least *medium* and a kit fingerprint exists,
  a new deterministic campaign id is proposed from the fingerprint.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from phishing_intel.config.settings import CorrelationSettings
from phishing_intel.database.repositories import SiteRepository
from phishing_intel.logging_config import get_logger
from phishing_intel.models.campaign import AttributionScore, CampaignMatch
from phishing_intel.models.findings import AnalysisResult, ConfidenceLevel
from phishing_intel.correlators.fingerprint_correlator import FingerprintCorrelator
from phishing_intel.correlators.infrastructure_correlator import (
    InfrastructureCorrelator,
)

logger = get_logger(__name__)


class CampaignCorrelator:
    """Top-level correlation engine producing an :class:`AttributionScore`."""

    def __init__(
        self,
        site_repository: SiteRepository,
        settings: CorrelationSettings,
    ) -> None:
        self.sites = site_repository
        self.settings = settings
        self.weights: Dict[str, int] = settings.weights
        # Compose the specialised sub-correlators.
        self.fingerprint = FingerprintCorrelator(site_repository, self.weights)
        self.infrastructure = InfrastructureCorrelator(site_repository, self.weights)

    def _brand_matches(self, result: AnalysisResult) -> List[CampaignMatch]:
        """Emit a ``same_brand`` signal if a prior site targets the same brand."""

        matches: List[CampaignMatch] = []
        brand = result.brand.target_brand if result.brand else None
        if brand:
            hits = self.sites.find_by_brand(brand)
            if hits:
                matches.append(
                    CampaignMatch(
                        signal="same_brand",
                        weight=self.weights.get("same_brand", 10),
                        detail=f"{len(hits)} prior site(s) impersonate brand '{brand}'",
                    )
                )
        return matches

    def _classify(self, score: int) -> ConfidenceLevel:
        """Map a numeric score to a confidence band using configured thresholds."""

        thresholds = self.settings.thresholds
        if score >= thresholds.high_min:
            return ConfidenceLevel.HIGH
        if score > thresholds.low:
            return ConfidenceLevel.MEDIUM
        return ConfidenceLevel.LOW

    def _resolve_campaign_id(self, result: AnalysisResult) -> Optional[str]:
        """Find the campaign id of any correlated historical site.

        Preference order: a site sharing the exact kit fingerprint, then a site
        sharing the DOM hash. The first that already belongs to a campaign wins.
        """

        candidate_sites = []
        fp = result.fingerprint
        if fp and fp.campaign_fingerprint:
            candidate_sites.extend(self.sites.find_by_fingerprint(fp.campaign_fingerprint))
        if fp and fp.dom_hash:
            candidate_sites.extend(self.sites.find_by_dom_hash(fp.dom_hash))
        for site in candidate_sites:
            if site.campaign is not None:
                return site.campaign.campaign_id
        return None

    def _propose_campaign_id(self, result: AnalysisResult) -> Optional[str]:
        """Deterministically derive a new campaign id from the kit fingerprint."""

        fp = result.fingerprint
        if fp and fp.campaign_fingerprint:
            brand = result.brand.target_brand if result.brand else "unknown"
            return f"CAMP-{brand}-{fp.campaign_fingerprint[:12]}"
        return None

    def correlate(self, result: AnalysisResult) -> AttributionScore:
        """Compute the attribution score for a sample.

        Parameters
        ----------
        result:
            The freshly analysed sample (must not yet be persisted, so it is not
            correlated against itself).

        Returns
        -------
        AttributionScore
            Score, confidence band, fired signals and attributed campaign id.
        """

        matches: List[CampaignMatch] = []
        matches.extend(self.fingerprint.correlate(result))
        matches.extend(self.infrastructure.correlate(result))
        matches.extend(self._brand_matches(result))

        # Weighted sum, capped and normalised to the 0-100 range.
        raw_score = sum(match.weight for match in matches)
        score = min(100, raw_score)
        confidence = self._classify(score)

        # Attribute to an existing campaign, or propose a new one when the
        # evidence is at least medium confidence.
        campaign_id = self._resolve_campaign_id(result)
        if campaign_id is None and confidence != ConfidenceLevel.LOW:
            campaign_id = self._propose_campaign_id(result)

        attribution = AttributionScore(
            score=score,
            confidence=confidence,
            matches=matches,
            matched_campaign_id=campaign_id,
        )
        logger.info(
            "corr.attribution",
            score=score,
            confidence=confidence.value,
            signals=[m.signal for m in matches],
            campaign_id=campaign_id,
        )
        return attribution
