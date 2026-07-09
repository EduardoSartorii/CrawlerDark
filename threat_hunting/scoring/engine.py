"""Configurable scoring engine."""

from __future__ import annotations

from threat_hunting.core.domain.entities import Finding, IndicatorType, ScorePolicy, Severity


class WeightedScoringEngine:
    """Calculate risk score from detections, indicators, source and recurrence."""

    def __init__(self, policy: ScorePolicy) -> None:
        self._policy = policy

    def score(self, finding: Finding) -> Finding:
        """Return a finding with score and severity derived from weights."""

        score = 0.0
        detections = finding.metadata.get("detections", [])
        score += sum(float(match.get("weight", 1.0)) for match in detections) * self._weight("detection")
        for indicator in finding.indicators:
            score += self._weight(indicator.type.value)
            if indicator.type in {IndicatorType.EMAIL, IndicatorType.CPF, IndicatorType.CNPJ, IndicatorType.CARD}:
                score += self._weight("credential")
        score += self._weight(f"source:{finding.source.lower()}")
        score += self._weight(f"category:{finding.category.lower()}")
        score = min(100.0, max(0.0, score))
        severity = self._severity_for(score)
        return finding.model_copy(update={"score": score, "severity": severity})

    def _weight(self, key: str) -> float:
        return float(self._policy.weights.get(key, 0.0))

    def _severity_for(self, score: float) -> Severity:
        selected = Severity.INFO
        for severity, threshold in self._policy.severity_thresholds.items():
            if score >= threshold:
                selected = severity
        return selected
