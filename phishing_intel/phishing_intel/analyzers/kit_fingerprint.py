"""Kit fingerprint builder used for campaign-level correlation."""

from __future__ import annotations

import hashlib

from phishing_intel.models.findings import DomAnalysisResult, FingerprintResult, JavaScriptAnalysisResult


class KitFingerprintAnalyzer:
    """Creates deterministic hash signatures for phishing kit reuse detection."""

    def build(self, dom: DomAnalysisResult, javascript: JavaScriptAnalysisResult) -> FingerprintResult:
        """Build DOM, asset, script and campaign fingerprints."""

        asset_hash = self._hash_collection(dom.assets)
        script_hash = self._hash_collection(javascript.script_hashes or dom.scripts)
        campaign_fingerprint = hashlib.sha256(
            f"{dom.dom_hash}:{asset_hash}:{script_hash}".encode("utf-8")
        ).hexdigest()
        return FingerprintResult(
            dom_hash=dom.dom_hash,
            asset_hash=asset_hash,
            script_hash=script_hash,
            campaign_fingerprint=campaign_fingerprint,
        )

    @staticmethod
    def _hash_collection(values: list[str]) -> str:
        """Build stable SHA256 for ordered, unique collection values."""

        payload = "\n".join(sorted(set(values)))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()
