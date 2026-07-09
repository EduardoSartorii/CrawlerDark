"""Kit fingerprinting analyzer.

Component responsibility
------------------------
Produce a stable, reusable fingerprint of a phishing *kit* so that future
incidents deploying the same kit can be automatically correlated. Emits a
:class:`~phishing_intel.models.findings.KitFingerprint`.

Fingerprint composition
-----------------------
* ``dom_hash``    - SHA256 of the normalised DOM skeleton (structure only).
* ``asset_hash``  - SHA256 over the set of asset *filenames* (order-independent).
* ``script_hash`` - SHA256 over the set of external script filenames.
* ``path_signature`` - the directory structure implied by asset/script paths.
* ``campaign_fingerprint`` - SHA256 of the three hashes above combined; this is
  the single value the correlation engine keys on.

Design rationale
----------------
Hashing *filenames and directory structure* (rather than raw bytes) means the
fingerprint survives trivial content edits but still uniquely identifies a kit
by its characteristic file layout (``/js/main.js``, ``/assets/style.css``, the
tell-tale ``next.php`` gate, ...).
"""

from __future__ import annotations

from typing import List, Optional
from urllib.parse import urlparse

from phishing_intel.logging_config import get_logger
from phishing_intel.models.findings import DOMAnalysis, KitFingerprint
from phishing_intel.utils import (
    dedupe_preserve_order,
    filename_from_url,
    sha256_of_iterable,
    sha256_text,
)

logger = get_logger(__name__)


class KitFingerprinter:
    """Build a :class:`KitFingerprint` from a DOM analysis."""

    def _path_signature(self, refs: List[str]) -> List[str]:
        """Derive the directory-structure signature from asset/script refs.

        For each reference we keep the *directory* portion of its path (dropping
        the filename and the host). ``https://x.com/kit/js/app.js`` becomes
        ``/kit/js``. The sorted, de-duplicated set of directories is the kit's
        structural path signature.
        """

        dirs: List[str] = []
        for ref in refs:
            if not ref:
                continue
            path = urlparse(ref if "://" in ref else f"http://x/{ref.lstrip('/')}").path
            directory = path.rsplit("/", 1)[0]
            if directory and directory != "/":
                dirs.append(directory)
        return sorted(set(dirs))

    def fingerprint(self, dom: DOMAnalysis) -> KitFingerprint:
        """Compute the kit fingerprint from a DOM analysis.

        Parameters
        ----------
        dom:
            The DOM analysis of the page.

        Returns
        -------
        KitFingerprint
        """

        # DOM hash: reuse the structural hash if present, else derive it.
        dom_hash = dom.structural_hash or sha256_text(dom.normalized_dom)

        # Asset filenames (images, css, iframes, ...).
        asset_names = [
            name for ref in dom.assets if (name := filename_from_url(ref))
        ]
        asset_hash = sha256_of_iterable(asset_names)

        # Script filenames (external scripts only; inline scripts are volatile).
        script_names = [
            name for ref in dom.scripts_external if (name := filename_from_url(ref))
        ]
        script_hash = sha256_of_iterable(script_names)

        path_signature = self._path_signature(dom.assets + dom.scripts_external)

        # The composite fingerprint binds the three structural hashes together.
        campaign_fingerprint = sha256_text(f"{dom_hash}:{asset_hash}:{script_hash}")

        fp = KitFingerprint(
            dom_hash=dom_hash,
            asset_hash=asset_hash,
            script_hash=script_hash,
            path_signature=dedupe_preserve_order(path_signature),
            campaign_fingerprint=campaign_fingerprint,
        )
        logger.info(
            "kit.fingerprinted",
            dom_hash=dom_hash,
            asset_hash=asset_hash,
            script_hash=script_hash,
            campaign_fingerprint=campaign_fingerprint,
        )
        return fp
