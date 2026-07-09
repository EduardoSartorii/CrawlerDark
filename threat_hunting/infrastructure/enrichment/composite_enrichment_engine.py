"""CompositeEnrichmentEngine — combina múltiplos provedores de enriquecimento."""

from __future__ import annotations

from collections.abc import Sequence

from ...core.domain.entities import Finding
from ...core.domain.ports import EnrichmentEnginePort


class CompositeEnrichmentEngine:
    def __init__(self, providers: Sequence[EnrichmentEnginePort]) -> None:
        self._providers = list(providers)

    async def enrich(self, finding: Finding) -> Finding:
        for provider in self._providers:
            try:
                finding = await provider.enrich(finding)
            except Exception as exc:  # noqa: BLE001 — enrichers são best-effort
                finding.record_event(
                    "enrich.error",
                    str(exc),
                    {"provider": type(provider).__name__},
                )
        return finding
