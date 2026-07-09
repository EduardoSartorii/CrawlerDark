"""NoopEnrichmentEngine — mantém o pipeline funcional sem chamadas externas."""

from __future__ import annotations

from ...core.domain.entities import Finding


class NoopEnrichmentEngine:
    async def enrich(self, finding: Finding) -> Finding:
        finding.record_event("enrich", "noop enrichment", {"provider": "noop"})
        return finding
