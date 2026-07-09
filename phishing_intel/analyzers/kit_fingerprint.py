"""
Phishing kit fingerprinting engine.

Generates composite fingerprints from DOM structure, assets,
JavaScript, and file naming patterns for campaign correlation.

Architectural Responsibility:
    Creates stable identifiers for phishing kit reuse detection.
    campaign_fingerprint enables linking future incidents to known kits.

Fingerprint Components:
    - dom_hash: SHA256 of normalized DOM structure
    - asset_hash: SHA256 of sorted asset URLs
    - script_hash: SHA256 of script content hashes
    - campaign_fingerprint: Composite SHA256 of all components
"""

from __future__ import annotations

from urllib.parse import urlparse

import structlog

from phishing_intel.models.findings import DOMFinding, JavaScriptFinding, KitFingerprint
from phishing_intel.utils import sha256_hash

logger = structlog.get_logger(__name__)


class KitFingerprinter:
    """
    Phishing kit fingerprint generator.

    Produces multi-component hashes that remain stable across
    deployments of the same kit with different domains.
    """

    def fingerprint(
        self,
        dom: DOMFinding,
        javascript: JavaScriptFinding,
    ) -> KitFingerprint:
        """
        Generate complete kit fingerprint.

        Args:
            dom: DOM analysis result.
            javascript: JavaScript analysis result.

        Returns:
            KitFingerprint with component and composite hashes.
        """
        logger.info("kit_fingerprinting_start")

        dom_hash = dom.structural_hash or sha256_hash(dom.normalized_dom)

        # Asset fingerprint from sorted asset URLs (domain-agnostic paths)
        asset_paths = sorted(
            self._normalize_path(a.url) for a in dom.assets if a.url
        )
        asset_hash = sha256_hash("|".join(asset_paths))

        # Script fingerprint from content hashes
        script_hashes = sorted(
            s.content_hash for s in dom.scripts if s.content_hash
        ) + ([javascript.script_hash] if javascript.script_hash else [])
        script_hash = sha256_hash("|".join(script_hashes))

        # Directory structure from asset/script paths
        directory_structure = self._extract_directory_structure(dom)

        # File naming patterns
        naming_patterns = self._extract_naming_patterns(dom.filenames)

        # Composite campaign fingerprint
        campaign_fp = sha256_hash(f"{dom_hash}|{asset_hash}|{script_hash}")

        result = KitFingerprint(
            dom_hash=dom_hash,
            asset_hash=asset_hash,
            script_hash=script_hash,
            campaign_fingerprint=campaign_fp,
            directory_structure=directory_structure,
            file_naming_patterns=naming_patterns,
        )

        logger.info(
            "kit_fingerprinting_complete",
            campaign_fingerprint=campaign_fp,
        )
        return result

    def _normalize_path(self, url: str) -> str:
        """Extract path from URL, ignoring domain for cross-deployment matching."""
        path = urlparse(url).path
        return path or "/"

    def _extract_directory_structure(self, dom: DOMFinding) -> list[str]:
        """Extract unique directory paths from assets and scripts."""
        dirs: set[str] = set()
        for asset in dom.assets:
            path = urlparse(asset.url).path
            if "/" in path:
                dir_path = "/".join(path.split("/")[:-1])
                if dir_path:
                    dirs.add(dir_path)
        for script in dom.scripts:
            if script.src:
                path = urlparse(script.src).path
                if "/" in path:
                    dir_path = "/".join(path.split("/")[:-1])
                    if dir_path:
                        dirs.add(dir_path)
        return sorted(dirs)

    def _extract_naming_patterns(self, filenames: list[str]) -> list[str]:
        """
        Identify common file naming conventions in kit.

        Patterns like login.php, index.html, style.css are
        characteristic of specific kit families.
        """
        patterns: list[str] = []
        for fn in filenames:
            if fn:
                # Extract extension and base pattern
                parts = fn.rsplit(".", 1)
                if len(parts) == 2:
                    patterns.append(f"*.{parts[1]}")
                patterns.append(fn)
        return sorted(set(patterns))
