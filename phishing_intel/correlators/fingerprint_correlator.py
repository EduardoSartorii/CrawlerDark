"""Fingerprint correlator.

Component responsibility
------------------------
Compare the kit fingerprint (and DOM/JS structural hashes) of a new sample
against historical records to detect kit reuse. Emits weighted
:class:`~phishing_intel.models.campaign.CampaignMatch` signals consumed by the
campaign correlator.

Signals produced
----------------
* ``same_fingerprint`` - identical composite ``campaign_fingerprint`` (kit reuse).
* ``same_dom_pattern`` - identical DOM structural hash.
* ``same_js_pattern``  - identical external-script hash.
"""

from __future__ import annotations

from typing import Dict, List

from phishing_intel.database.repositories import SiteRepository
from phishing_intel.logging_config import get_logger
from phishing_intel.models.campaign import CampaignMatch
from phishing_intel.models.findings import AnalysisResult

logger = get_logger(__name__)


class FingerprintCorrelator:
    """Correlate a sample against history using kit/structural fingerprints."""

    def __init__(self, site_repository: SiteRepository, weights: Dict[str, int]) -> None:
        self.sites = site_repository
        self.weights = weights

    def correlate(self, result: AnalysisResult) -> List[CampaignMatch]:
        """Return the fingerprint-based matches for ``result``.

        Business rule: an identical composite fingerprint is the single
        strongest attribution signal (kit reuse), so it carries the largest
        weight. DOM- and script-hash matches are weaker corroborating signals.
        """

        matches: List[CampaignMatch] = []
        if result.fingerprint is None:
            return matches

        fp = result.fingerprint

        # --- Exact kit reuse (composite fingerprint) -----------------------
        if fp.campaign_fingerprint:
            hits = self.sites.find_by_fingerprint(fp.campaign_fingerprint)
            if hits:
                matches.append(
                    CampaignMatch(
                        signal="same_fingerprint",
                        weight=self.weights.get("same_fingerprint", 40),
                        detail=f"{len(hits)} prior site(s) share kit fingerprint {fp.campaign_fingerprint[:12]}",
                    )
                )

        # --- DOM structural-hash reuse -------------------------------------
        if fp.dom_hash:
            dom_hits = self.sites.find_by_dom_hash(fp.dom_hash)
            if dom_hits:
                matches.append(
                    CampaignMatch(
                        signal="same_dom_pattern",
                        weight=self.weights.get("same_dom_pattern", 20),
                        detail=f"{len(dom_hits)} prior site(s) share DOM hash {fp.dom_hash[:12]}",
                    )
                )

        # --- External-script hash reuse ------------------------------------
        # We compare against persisted results' script hashes; a stored site
        # with the same script_hash indicates a shared JS bundle.
        if fp.script_hash:
            js_hits = self._find_by_script_hash(fp.script_hash)
            if js_hits:
                matches.append(
                    CampaignMatch(
                        signal="same_js_pattern",
                        weight=self.weights.get("same_js_pattern", 15),
                        detail=f"{js_hits} prior site(s) share script hash {fp.script_hash[:12]}",
                    )
                )

        logger.info("corr.fingerprint", matches=[m.signal for m in matches])
        return matches

    def _find_by_script_hash(self, script_hash: str) -> int:
        """Count persisted sites whose fingerprint has the same script hash.

        Implemented by scanning the (indexed) fingerprint rows through the
        site repository's persisted JSON is avoided; instead we reuse the
        DOM-hash join path by loading fingerprints directly.
        """

        count = 0
        for site in self.sites.list_all():
            if site.fingerprint and site.fingerprint.script_hash == script_hash:
                count += 1
        return count
