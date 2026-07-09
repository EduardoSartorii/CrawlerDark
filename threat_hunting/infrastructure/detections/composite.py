"""CompositeDetectionEngine — combina múltiplos detectores em série."""

from __future__ import annotations

from collections.abc import Sequence

from ...core.domain.entities import Finding
from ...core.domain.ports import DetectionEnginePort


class CompositeDetectionEngine:
    """Aplica detectores na ordem fornecida (Strategy + Composite)."""

    def __init__(self, detectors: Sequence[DetectionEnginePort]) -> None:
        self._detectors = list(detectors)

    async def detect(self, finding: Finding) -> Finding:
        for detector in self._detectors:
            finding = await detector.detect(finding)
        return finding
