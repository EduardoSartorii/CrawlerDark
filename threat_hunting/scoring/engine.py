"""Scoring engine with configurable weighted factors."""

from __future__ import annotations

from collections.abc import Sequence

from threat_hunting.core.contracts import ScoringEnginePort
from threat_hunting.domain.entities import ExecutionContext, Finding, Severity
from threat_hunting.domain.rules import ScoreWeights


class WeightedScoringEngine(ScoringEnginePort):
    """Score findings with transparent weighted breakdown."""

    def __init__(self, weights: ScoreWeights, critical_threshold: float = 70.0) -> None:
        self._weights = weights
        self._critical_threshold = critical_threshold

    def process(self, findings: Sequence[Finding], context: ExecutionContext) -> Sequence[Finding]:
        """Calculate score and confidence based on configured factors."""
        for finding in findings:
            factors: dict[str, float] = {}
            matched_rules = finding.metadata.get("matched_rules", [])
            if matched_rules:
                factors["rule_matches"] = len(matched_rules) * self._weights.regex_match

            ioc_count = len(finding.indicators)
            if ioc_count > 0:
                factors["ioc_quantity"] = ioc_count * self._weights.ioc_quantity

            if any(i.type == "email" for i in finding.indicators):
                factors["emails"] = self._weights.emails
            if any(i.type == "domain" for i in finding.indicators):
                factors["domain"] = self._weights.domain

            if "vip" in finding.tags:
                factors["vip_match"] = self._weights.vip_match
            if any(tag.startswith("rule:") for tag in finding.tags):
                factors["context"] = self._weights.context

            total = round(sum(factors.values()), 2)
            finding.score_breakdown.factors = factors
            finding.score_breakdown.total = total
            finding.score = total
            finding.confidence = min(1.0, 0.4 + min(total / 100, 0.6))
            finding.severity = self._severity_from_score(total)
            finding.touch()
        return findings

    def _severity_from_score(self, score: float) -> Severity:
        if score >= self._critical_threshold:
            return Severity.CRITICAL
        if score >= 50:
            return Severity.HIGH
        if score >= 25:
            return Severity.MEDIUM
        return Severity.LOW
