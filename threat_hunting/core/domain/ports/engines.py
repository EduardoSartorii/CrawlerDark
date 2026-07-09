"""Ports para os engines do pipeline (detection, scoring, correlation, ...)."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol, runtime_checkable

from ..entities import Finding
from ..value_objects import Score


@runtime_checkable
class DetectionEnginePort(Protocol):
    async def detect(self, finding: Finding) -> Finding: ...


@runtime_checkable
class ScoringEnginePort(Protocol):
    async def score(self, finding: Finding) -> Score: ...


@runtime_checkable
class CorrelationEnginePort(Protocol):
    async def correlate(self, finding: Finding, corpus: Sequence[Finding]) -> Finding: ...


@runtime_checkable
class DeduplicationEnginePort(Protocol):
    async def deduplicate(
        self, finding: Finding, corpus: Sequence[Finding]
    ) -> tuple[Finding, bool]:
        """Retorna ``(finding, is_duplicate)``.

        Se duplicata, ``finding.dedup_hash`` já aponta para o hash canônico.
        Consumidores decidem se descartam ou fazem merge.
        """
        ...


@runtime_checkable
class EnrichmentEnginePort(Protocol):
    async def enrich(self, finding: Finding) -> Finding: ...
