"""Detection engine that evaluates dynamic rules loaded from repositories."""

from __future__ import annotations

import re
from collections.abc import Sequence

from threat_hunting.core.contracts import DetectionEnginePort, RuleRepositoryPort
from threat_hunting.domain.entities import ExecutionContext, Finding, Severity
from threat_hunting.domain.rules import DetectionRule, RuleType


class DynamicDetectionEngine(DetectionEnginePort):
    """Rule-driven detection engine without hardcoded business rules."""

    def __init__(self, rule_repository: RuleRepositoryPort) -> None:
        self._rule_repository = rule_repository

    def process(self, findings: Sequence[Finding], context: ExecutionContext) -> Sequence[Finding]:
        """Evaluate all enabled rules and attach tags and metadata."""
        active_rules = [
            rule
            for rule in self._rule_repository.load_detection_rules()
            if rule.enabled
        ]
        for finding in findings:
            for rule in active_rules:
                if self._matches(rule, finding):
                    finding.add_tag(f"rule:{rule.name}")
                    finding.metadata.setdefault("matched_rules", []).append(rule.rule_id)
                    if rule.rule_type in {RuleType.BLACKLIST, RuleType.THREAT_ACTOR_MATCH}:
                        finding.severity = Severity.CRITICAL
            finding.touch()
        return findings

    @staticmethod
    def _matches(rule: DetectionRule, finding: Finding) -> bool:
        searchable = " ".join(
            [
                finding.title,
                finding.description,
                " ".join(finding.tags),
                " ".join(i.value for i in finding.indicators),
            ]
        ).lower()
        expression = rule.expression.lower()

        if rule.rule_type in {RuleType.KEYWORD, RuleType.THREAT_ACTOR_MATCH, RuleType.IOC_MATCH}:
            return expression in searchable
        if rule.rule_type in {RuleType.BLACKLIST, RuleType.WHITELIST}:
            return expression in searchable
        if rule.rule_type == RuleType.REGEX:
            return bool(re.search(rule.expression, searchable))
        if rule.rule_type in {RuleType.YARA, RuleType.SIGMA, RuleType.HEURISTIC}:
            return expression in searchable
        if rule.rule_type == RuleType.THRESHOLD:
            threshold = float(rule.metadata.get("min_indicators", 1))
            return float(len(finding.indicators)) >= threshold
        if rule.rule_type == RuleType.COMPOSITE:
            terms = [term.strip() for term in expression.split("&&") if term.strip()]
            return all(term in searchable for term in terms)
        return False
