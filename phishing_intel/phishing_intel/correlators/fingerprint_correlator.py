"""Fingerprint correlator for comparing kit similarities."""

from __future__ import annotations

from phishing_intel.models.findings import FingerprintResult


class FingerprintCorrelator:
    """Correlates current fingerprint against historical records."""

    def correlate(self, current: FingerprintResult, historical: list[FingerprintResult]) -> list[tuple[FingerprintResult, int]]:
        """Return matching fingerprints with similarity score."""

        results: list[tuple[FingerprintResult, int]] = []
        for item in historical:
            score = 0
            if current.campaign_fingerprint == item.campaign_fingerprint:
                score += 70
            if current.dom_hash == item.dom_hash:
                score += 15
            if current.script_hash == item.script_hash:
                score += 10
            if current.asset_hash == item.asset_hash:
                score += 5
            if score:
                results.append((item, min(score, 100)))
        return sorted(results, key=lambda pair: pair[1], reverse=True)
