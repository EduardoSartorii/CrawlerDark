"""EnrichmentEngine.

Responsibility
--------------
Run every registered enrichment provider over a finding's indicators. Providers
are Strategy objects added without touching the engine. A provider failure is
isolated so one flaky enrichment source cannot break the pipeline.
"""

from __future__ import annotations

from collections.abc import Sequence

from threat_hunting.core.application.ports.enrichment import EnrichmentProvider
from threat_hunting.core.domain.entities.finding import Finding


class EnrichmentEngine:
    """Applies enrichment providers to a finding's indicators."""

    def __init__(self, providers: Sequence[EnrichmentProvider] = ()) -> None:
        self._providers = list(providers)

    def enrich(self, finding: Finding) -> Finding:
        """Enrich a finding in place using all supporting providers."""
        applied = 0
        for indicator in list(finding.indicators):
            for provider in self._providers:
                if not provider.supports(indicator):
                    continue
                try:
                    provider.enrich(finding, indicator)
                    applied += 1
                except Exception:  # isolate provider failures
                    finding.metadata.setdefault("enrichment_errors", []).append(provider.name)
        if applied:
            finding.record("enriched", f"{applied} enrichment(s) applied")
        return finding
