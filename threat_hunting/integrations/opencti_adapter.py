"""OpenCTI adapter placeholder for future integration."""

from __future__ import annotations

from threat_hunting.domain.entities import Finding


class OpenCTIAdapter:
    """Adapter interface for OpenCTI export integration."""

    def export_findings(self, findings: list[Finding]) -> None:
        return
