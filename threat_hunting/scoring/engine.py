"""Configurable weighted scoring engine."""

from __future__ import annotations

from collections.abc import Sequence

from threat_hunting.core.domain.entities import Finding, Severity
from threat_hunting.core.domain.rules import RuleMatch, ScoringProfile


class WeightedScoringEngine:
    """Calculate finding score from matches, source reputation, and context."""

    def __init__(self, profile: ScoringProfile) -> None:
        self.profile = profile

    def score(self, finding: Finding, matches: Sequence[RuleMatch]) -> Finding:
        """Return a scored finding using configurable weights."""

        score = self.profile.base_score
        score += sum(match.weight * self.profile.weights.get(match.rule_type.value, 1.0) for match in matches)
        score += len(finding.indicators) * self.profile.weights.get("indicator_count", 1.0)
        score += self.profile.weights.get(f"source:{finding.source}", 0.0)
        score += self.profile.weights.get(f"category:{finding.category}", 0.0)
        if any(tag in {"vip", "credential", "card", "leak"} for match in matches for tag in match.tags):
            score += self.profile.weights.get("sensitive_match", 10.0)
        severity = self._severity(score)
        tags = sorted({*finding.tags, *(tag for match in matches for tag in match.tags)})
        metadata = {**finding.metadata, "detections": [match.model_dump(mode="json") for match in matches]}
        return finding.model_copy(update={"tags": tags, "metadata": metadata}).with_score(score, severity)

    def _severity(self, score: float) -> Severity:
        """Map score to normalized severity thresholds."""

        thresholds = self.profile.severity_thresholds
        if score >= thresholds.get("critical", 85.0):
            return Severity.CRITICAL
        if score >= thresholds.get("high", 65.0):
            return Severity.HIGH
        if score >= thresholds.get("medium", 35.0):
            return Severity.MEDIUM
        if score >= thresholds.get("low", 10.0):
            return Severity.LOW
        return Severity.INFO
