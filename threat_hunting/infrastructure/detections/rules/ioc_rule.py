"""IOC-match detection rule.

Responsibility
--------------
Fire once per indicator already attached to the finding, weighting by indicator
type. High-value observables (credentials, cards, wallets, CPF/CNPJ) contribute
more than a bare domain. Weights are configurable via the constructor mapping.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from threat_hunting.core.domain.entities.finding import Finding
from threat_hunting.core.domain.enums import IndicatorType
from threat_hunting.core.domain.value_objects.score import DetectionMatch

# Default per-type weights (overridable via config).
_DEFAULT_WEIGHTS: dict[IndicatorType, float] = {
    IndicatorType.CREDENTIAL: 25.0,
    IndicatorType.CREDIT_CARD: 25.0,
    IndicatorType.CPF: 20.0,
    IndicatorType.CNPJ: 20.0,
    IndicatorType.BTC_WALLET: 15.0,
    IndicatorType.ETH_WALLET: 15.0,
    IndicatorType.EMAIL: 8.0,
    IndicatorType.MD5: 10.0,
    IndicatorType.SHA1: 10.0,
    IndicatorType.SHA256: 12.0,
    IndicatorType.IPV4: 8.0,
    IndicatorType.URL: 6.0,
    IndicatorType.DOMAIN: 5.0,
    IndicatorType.CVE: 12.0,
}


class IocMatchRule:
    """Scores a finding based on the indicators it already carries."""

    rule_type = "ioc"

    def __init__(
        self, rule_id: str = "ioc.presence", weights: Mapping[IndicatorType, float] | None = None
    ) -> None:
        self.rule_id = rule_id
        self._weights = dict(_DEFAULT_WEIGHTS)
        if weights:
            self._weights.update(weights)

    def evaluate(self, finding: Finding) -> Sequence[DetectionMatch]:
        """Return one match per indicator, weighted by its type."""
        matches: list[DetectionMatch] = []
        for indicator in finding.indicators:
            weight = self._weights.get(indicator.type, 4.0)
            matches.append(
                DetectionMatch(
                    rule_id=self.rule_id,
                    rule_type=self.rule_type,
                    matched=indicator.key,
                    weight=weight,
                    category=indicator.type.value,
                )
            )
        return matches
