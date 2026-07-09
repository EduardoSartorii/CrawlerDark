"""Configurable detection engine.

No business detection is hardcoded. Operators load rule definitions from YAML,
databases, or the future Django admin panel; this engine only applies rule
strategies to canonical findings.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from threat_hunting.core.domain.entities import Finding
from threat_hunting.core.domain.rules import DetectionRule, RuleMatch, RuleType


class ConfigurableDetectionEngine:
    """Evaluate dynamic detection rules against findings."""

    def __init__(self, rules: Iterable[DetectionRule]) -> None:
        self.rules = [rule for rule in rules if rule.enabled]

    def evaluate(self, finding: Finding) -> list[RuleMatch]:
        """Return rule matches for a finding."""

        text = self._searchable_text(finding)
        matches: list[RuleMatch] = []
        for rule in self.rules:
            if rule.type == RuleType.REGEX and rule.pattern:
                matches.extend(self._regex_matches(rule, text))
            elif rule.type in {RuleType.KEYWORD, RuleType.IOC, RuleType.BLACKLIST}:
                matches.extend(self._value_matches(rule, text))
            elif rule.type == RuleType.WHITELIST and self._value_matches(rule, text):
                return []
            elif rule.type == RuleType.THRESHOLD and len(finding.indicators) >= int(rule.metadata.get("count", 1)):
                matches.append(self._match(rule, f"indicator_count:{len(finding.indicators)}"))
            elif rule.type in {RuleType.YARA, RuleType.SIGMA, RuleType.HEURISTIC, RuleType.COMPOUND}:
                matches.extend(self._metadata_driven_matches(rule, finding, text))
        return matches

    @staticmethod
    def _searchable_text(finding: Finding) -> str:
        """Build lower-case searchable text from canonical fields."""

        parts = [
            finding.title,
            finding.description,
            " ".join(finding.tags),
            str(finding.raw_data),
            str(finding.normalized_data),
            " ".join(indicator.value for indicator in finding.indicators),
        ]
        return " ".join(parts).lower()

    def _regex_matches(self, rule: DetectionRule, text: str) -> list[RuleMatch]:
        """Apply regex rule."""

        assert rule.pattern is not None
        return [self._match(rule, match.group(0)) for match in re.finditer(rule.pattern, text, flags=re.IGNORECASE)]

    def _value_matches(self, rule: DetectionRule, text: str) -> list[RuleMatch]:
        """Apply keyword, IOC, blacklist, and whitelist value rules."""

        return [self._match(rule, value) for value in rule.values if value.lower() in text]

    def _metadata_driven_matches(self, rule: DetectionRule, finding: Finding, text: str) -> list[RuleMatch]:
        """Apply external rule placeholders driven by metadata selectors."""

        selector = str(rule.metadata.get("selector", "")).lower()
        expected = str(rule.metadata.get("contains", "")).lower()
        if selector == "tag" and expected in [tag.lower() for tag in finding.tags]:
            return [self._match(rule, expected)]
        if selector == "text" and expected and expected in text:
            return [self._match(rule, expected)]
        return []

    @staticmethod
    def _match(rule: DetectionRule, value: str) -> RuleMatch:
        """Create a normalized rule match."""

        return RuleMatch(
            rule_name=rule.name,
            rule_type=rule.type,
            value=value,
            weight=rule.weight,
            confidence=rule.confidence,
            tags=rule.tags,
            metadata=rule.metadata,
        )
