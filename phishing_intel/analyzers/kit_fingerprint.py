"""Phishing kit fingerprint generation.

Fingerprints combine normalized DOM structure, asset paths, script paths, and
file naming conventions. This lets analysts correlate future incidents even
when URLs or hosting providers rotate.
"""

from __future__ import annotations

from pathlib import PurePosixPath
from urllib.parse import urlparse

from phishing_intel.models.findings import DomFinding, JavaScriptFinding, KitFingerprintFinding
from phishing_intel.utils import sha256_text


class KitFingerprinter:
    """Create reusable fingerprints from DOM, assets, and JavaScript."""

    def fingerprint(self, dom: DomFinding, javascript: JavaScriptFinding) -> KitFingerprintFinding:
        """Return hashes and a campaign fingerprint for a phishing kit."""

        paths = [urlparse(value).path for value in dom.assets + dom.scripts + dom.links if value]
        directories = sorted({str(PurePosixPath(path).parent) for path in paths if path and path != "/"})
        file_names = sorted(set(dom.file_names))
        asset_material = "\n".join(sorted(dom.assets + file_names + directories))
        script_material = "\n".join(sorted(dom.scripts + javascript.hardcoded_urls + javascript.suspicious_strings))
        dom_sha = dom.dom_hash or sha256_text(dom.normalized_dom)
        asset_sha = sha256_text(asset_material)
        script_sha = sha256_text(script_material)
        campaign_fingerprint = sha256_text("|".join([dom_sha, asset_sha, script_sha]))
        return KitFingerprintFinding(
            dom_sha256=dom_sha,
            asset_sha256=asset_sha,
            script_sha256=script_sha,
            campaign_fingerprint=campaign_fingerprint,
            directories=directories,
            file_names=file_names,
        )
