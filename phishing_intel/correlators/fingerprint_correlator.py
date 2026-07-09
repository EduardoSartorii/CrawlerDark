"""
Fingerprint-based correlation module.

Links incidents through kit fingerprints, DOM hashes, and
script hashes for campaign clustering.

Architectural Responsibility:
    Content-similarity correlation complementing infrastructure
    and certificate-based linking.
"""

from __future__ import annotations

import structlog

from phishing_intel.database.repositories import FingerprintRepository, PhishingSiteRepository
from phishing_intel.database.session import get_session
from phishing_intel.models.findings import KitFingerprint

logger = structlog.get_logger(__name__)


class FingerprintCorrelator:
    """Kit fingerprint correlation engine."""

    def find_matches(self, fingerprint: KitFingerprint) -> list[dict[str, str]]:
        """
        Find historical incidents matching fingerprint components.

        Args:
            fingerprint: Kit fingerprint to match.

        Returns:
            List of match records with type and URL.
        """
        logger.info(
            "fingerprint_correlation_start",
            campaign_fingerprint=fingerprint.campaign_fingerprint,
        )

        matches: list[dict[str, str]] = []

        with get_session() as session:
            fp_repo = FingerprintRepository(session)

            if fingerprint.campaign_fingerprint:
                existing = fp_repo.get_by_campaign_fingerprint(
                    fingerprint.campaign_fingerprint
                )
                if existing:
                    matches.append({
                        "match_type": "campaign_fingerprint",
                        "value": fingerprint.campaign_fingerprint,
                        "url": existing.site_url,
                    })

        logger.info("fingerprint_correlation_complete", matches=len(matches))
        return matches

    def similarity_score(
        self, fp_a: KitFingerprint, fp_b: KitFingerprint
    ) -> float:
        """
        Calculate similarity score between two fingerprints.

        Args:
            fp_a: First fingerprint.
            fp_b: Second fingerprint.

        Returns:
            Similarity score 0-100.
        """
        score = 0.0
        if fp_a.campaign_fingerprint and fp_a.campaign_fingerprint == fp_b.campaign_fingerprint:
            return 100.0
        if fp_a.dom_hash == fp_b.dom_hash:
            score += 40.0
        if fp_a.script_hash == fp_b.script_hash:
            score += 35.0
        if fp_a.asset_hash == fp_b.asset_hash:
            score += 25.0
        return min(score, 100.0)
