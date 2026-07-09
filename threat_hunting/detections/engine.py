"""Dynamic detection engine.

Rules are loaded from repositories/configuration and support regex, keyword,
IOC, threat actor, whitelist, blacklist, threshold and compound rule metadata.
The implementation keeps rule execution deterministic and extensible through
strategy dispatch by rule kind.
"""

from __future__ import annotations

import re

from threat_hunting.core.domain.entities import DetectionRule, Finding, Severity


class InMemoryDetectionRuleRepository:
    """Simple rule repository backed by configured Pydantic models."""

    def __init__(self, rules: list[DetectionRule]) -> None:
        self._rules = rules

    def list_enabled(self) -> list[DetectionRule]:
        """Return enabled rules."""

        return [rule for rule in self._rules if rule.enabled]


class RuleBasedDetectionEngine:
    """Apply configured rules and annotate matching findings."""

    def __init__(self, rules: list[DetectionRule]) -> None:
        self._rules = [rule for rule in rules if rule.enabled]

    def detect(self, finding: Finding) -> Finding:
        """Return a finding with detection metadata, tags and severity."""

        text = " ".join(
            [
                finding.title,
                finding.description,
                str(finding.normalized_data),
                " ".join(indicator.value for indicator in finding.indicators),
            ]
        )
        matches: list[dict[str, object]] = []
        tags = set(finding.tags)
        severity = finding.severity
        for rule in self._rules:
            if self._matches(rule, text, finding):
                matches.append({"id": rule.id, "name": rule.name, "kind": rule.kind, "weight": rule.weight})
                tags.update(rule.tags)
                severity = self._max_severity(severity, rule.severity)
        metadata = dict(finding.metadata)
        metadata["detections"] = matches
        return finding.model_copy(update={"metadata": metadata, "tags": sorted(tags), "severity": severity})

    def _matches(self, rule: DetectionRule, text: str, finding: Finding) -> bool:
        kind = rule.kind.lower()
        if kind in {"regex", "yara", "sigma", "heuristic", "compound"}:
            return re.search(rule.pattern, text, re.IGNORECASE) is not None
        if kind in {"keyword", "threat_actor", "blacklist"}:
            return rule.pattern.lower() in text.lower()
        if kind == "ioc":
            return any(rule.pattern.lower() in indicator.value.lower() for indicator in finding.indicators)
        if kind == "whitelist":
            return rule.pattern.lower() not in text.lower()
        if kind == "threshold":
            return finding.score >= float(rule.pattern)
        return False

    @staticmethod
    def _max_severity(left: Severity, right: Severity) -> Severity:
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order[max(order.index(left), order.index(right))]
