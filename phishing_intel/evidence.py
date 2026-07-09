"""Evidence store (OPSEC / chain of custody).

Component responsibility
------------------------
Preserve the raw artifacts and analysis outputs of every sample in an
append-only, timestamped, hash-indexed directory structure. This provides the
auditable chain of custody required for professional CTI operations and keeps
*collection* cleanly separated from *analysis*.

Layout
------
``<evidence_dir>/<domain>/<timestamp>-<html_hash8>/``
    ``manifest.json``    - timestamp, URL, hashes, certificate summary, verdict.
    ``page.html``        - raw HTML.
    ``scripts.js``       - concatenated raw JavaScript.
    ``iocs.txt``         - extracted IOCs, one per line.
    ``analysis.json``    - full serialised :class:`AnalysisResult`.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from phishing_intel.logging_config import get_logger
from phishing_intel.models.findings import AnalysisResult
from phishing_intel.utils import sha256_text

logger = get_logger(__name__)


class EvidenceStore:
    """Persist raw artifacts + analysis outputs to disk for chain of custody."""

    def __init__(self, base_dir: str) -> None:
        self.base_dir = Path(base_dir)

    def _safe_component(self, value: Optional[str]) -> str:
        """Sanitise a string into a filesystem-safe path component."""

        cleaned = (value or "unknown").strip().lower()
        return "".join(c if c.isalnum() or c in {".", "-", "_"} else "_" for c in cleaned)

    def store(
        self,
        result: AnalysisResult,
        html: Optional[str],
        scripts: Optional[List[str]] = None,
    ) -> Path:
        """Persist a sample's evidence and return the created directory.

        Parameters
        ----------
        result:
            The completed analysis (its hashes/verdict go into the manifest).
        html:
            Raw HTML to preserve (may be ``None`` when unavailable).
        scripts:
            Raw JavaScript blobs to preserve.

        Returns
        -------
        Path
            The directory containing the stored evidence.
        """

        timestamp = datetime.now(timezone.utc)
        stamp = timestamp.strftime("%Y%m%dT%H%M%S")
        html_hash = result.html_hash or (sha256_text(html) if html else "nohtml")
        directory = (
            self.base_dir
            / self._safe_component(result.domain or result.url)
            / f"{stamp}-{html_hash[:8]}"
        )
        directory.mkdir(parents=True, exist_ok=True)

        # Raw artifacts.
        if html is not None:
            (directory / "page.html").write_text(html, encoding="utf-8")
        if scripts:
            (directory / "scripts.js").write_text("\n\n".join(scripts), encoding="utf-8")
        if result.iocs:
            (directory / "iocs.txt").write_text("\n".join(result.iocs), encoding="utf-8")

        # Full analysis snapshot (lossless).
        (directory / "analysis.json").write_text(
            result.model_dump_json(indent=2), encoding="utf-8"
        )

        # Audit manifest summarising the chain of custody.
        manifest = {
            "timestamp": timestamp.isoformat(),
            "url": result.url,
            "domain": result.domain,
            "html_hash": result.html_hash,
            "javascript_hash": result.javascript_hash,
            "certificate": (
                {
                    "serial_number": result.certificate.serial_number,
                    "sha256_fingerprint": result.certificate.sha256_fingerprint,
                }
                if result.certificate
                else None
            ),
            "verdict": {
                "phishing_type": (
                    result.classification.primary_type.value
                    if result.classification
                    else None
                ),
                "target_brand": result.brand.target_brand if result.brand else None,
            },
        }
        (directory / "manifest.json").write_text(
            json.dumps(manifest, indent=2), encoding="utf-8"
        )

        logger.info("evidence.stored", directory=str(directory), url=result.url)
        return directory
