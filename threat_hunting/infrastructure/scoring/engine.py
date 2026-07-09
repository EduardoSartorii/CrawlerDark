"""ScoringEngine.

Responsibility
--------------
Compute an explainable 0-100 :class:`Score` for a finding from its detection
matches, indicator quantity, source reputation and recurrence — every factor
weighted by the configurable :class:`ScoringWeights`. The engine records a
per-component breakdown so the resulting score is fully auditable, then updates
the finding's severity accordingly.

This is a Strategy over the scoring model: swapping the weights (or the whole
engine) changes scoring without affecting any other stage.
"""

from __future__ import annotations

from threat_hunting.core.domain.entities.finding import Finding
from threat_hunting.core.domain.value_objects.score import Score
from threat_hunting.infrastructure.scoring.weights import ScoringWeights


class ScoringEngine:
    """Weighted, explainable scoring of findings."""

    def __init__(self, weights: ScoringWeights | None = None) -> None:
        self._weights = weights or ScoringWeights()

    def score(self, finding: Finding, *, recurrence: bool = False) -> Score:
        """Compute, apply and return the finding's score.

        :param recurrence: whether this finding's indicators have been seen
            before (adds the configured recurrence bonus).
        """
        score = Score.zero()

        # 1. Detection matches, each scaled by its rule-type multiplier.
        for match in finding.detections:
            multiplier = self._weights.multiplier_for_rule(match.rule_type)
            score = score.with_component(f"rule:{match.rule_type}", match.weight * multiplier)

        # 2. IOC quantity bonus (capped).
        if finding.indicators:
            bonus = min(
                self._weights.ioc_quantity_cap,
                len(finding.indicators) * self._weights.ioc_quantity_bonus,
            )
            score = score.with_component("ioc_quantity", bonus)

        # 3. Recurrence/history bonus.
        if recurrence:
            score = score.with_component("recurrence", self._weights.recurrence_bonus)

        # 4. Source reputation as a final multiplier on the accumulated value.
        source_type = str(finding.metadata.get("source_type", ""))
        reputation = self._weights.reputation_for_source(source_type)
        if reputation != 1.0 and score.value > 0:
            uplift = min(100.0, score.value * reputation) - score.value
            score = score.with_component("source_reputation", uplift)

        finding.set_score(score)
        finding.record("scored", f"score={score.value:.1f}", severity=finding.severity.value)
        return score
