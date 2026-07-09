"""Fingerprint comparison helpers."""

from __future__ import annotations

from phishing_intel.models.findings import KitFingerprintFinding


class FingerprintCorrelator:
    """Compare kit fingerprints across incidents."""

    def compare(self, left: KitFingerprintFinding, right: KitFingerprintFinding) -> dict[str, bool]:
        """Return field-level fingerprint matches."""

        return {
            "campaign_fingerprint": left.campaign_fingerprint == right.campaign_fingerprint,
            "dom_hash": left.dom_sha256 == right.dom_sha256,
            "asset_hash": left.asset_sha256 == right.asset_sha256,
            "script_hash": left.script_sha256 == right.script_sha256,
        }
