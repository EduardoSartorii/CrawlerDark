"""The enrichment engine.

Responsibility
--------------
Implement :class:`EnrichmentEnginePort`. Enrichment adds analyst-useful context
that the raw source did not provide: defanging dangerous indicators for safe
display, tagging the observable mix, flagging Brazilian fraud artefacts and
computing a compact indicator breakdown. Network-backed enrichment providers
(GreyNoise, VirusTotal, AbuseIPDB, Shodan, ...) plug in through the same port as
additional providers without changing the pipeline.

Business rules
--------------
* Enrichment is additive and must never lower the fidelity of the finding.
* Indicators that could be dangerous if clicked (URLs, IPs, domains) are defanged
  in a derived, display-safe field while the original value is preserved.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence

from threat_hunting.core.application.ports.pipeline_stages import (
    EnrichmentEnginePort,
)
from threat_hunting.core.domain.entities import Finding, Indicator
from threat_hunting.core.domain.enums import IndicatorType

_DEFANG_TYPES = {IndicatorType.URL, IndicatorType.IPV4, IndicatorType.DOMAIN}


class EnrichmentProvider:
    """Base class for pluggable enrichment providers (Strategy)."""

    name = "abstract"

    def enrich(self, finding: Finding) -> None:  # pragma: no cover - interface
        """Mutate the finding in place with additional context."""
        raise NotImplementedError


class DefangProvider(EnrichmentProvider):
    """Adds a display-safe defanged form for dangerous indicators."""

    name = "defang"

    def enrich(self, finding: Finding) -> None:
        for indicator in finding.indicators:
            if indicator.type in _DEFANG_TYPES and not indicator.defanged:
                indicator.context["defanged"] = self._defang(indicator.value)
                indicator.defanged = True

    @staticmethod
    def _defang(value: str) -> str:
        """Neutralise an indicator for safe rendering."""
        return (
            value.replace("http", "hxxp")
            .replace(".", "[.]")
            .replace("://", "[://]")
        )


class TaggingProvider(EnrichmentProvider):
    """Adds high-level tags describing the observable mix."""

    name = "tagging"

    def enrich(self, finding: Finding) -> None:
        types = {i.type for i in finding.indicators}
        if {IndicatorType.CPF, IndicatorType.CNPJ} & types:
            finding.add_tag("br-fraud")
        if IndicatorType.CREDIT_CARD in types:
            finding.add_tag("carding")
        if IndicatorType.CREDENTIAL in types:
            finding.add_tag("credentials")
        if {IndicatorType.BTC_WALLET, IndicatorType.ETH_WALLET} & types:
            finding.add_tag("crypto")


class EnrichmentEngine(EnrichmentEnginePort):
    """Runs a chain of enrichment providers over a finding."""

    def __init__(self, providers: Sequence[EnrichmentProvider] | None = None) -> None:
        self._providers = list(providers) if providers else [
            DefangProvider(),
            TaggingProvider(),
        ]

    def enrich(self, finding: Finding) -> Finding:
        """Apply every provider and attach an indicator breakdown."""
        for provider in self._providers:
            provider.enrich(finding)
        breakdown = Counter(i.type.value for i in finding.indicators)
        finding.metadata["enrichment"] = {
            "indicator_breakdown": dict(breakdown),
            "providers": [p.name for p in self._providers],
        }
        finding.record("enrichment", f"applied {len(self._providers)} provider(s)")
        return finding
