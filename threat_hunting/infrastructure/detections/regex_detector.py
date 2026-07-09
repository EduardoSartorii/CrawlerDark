"""RegexDetector — carrega regras YAML e aplica sobre o texto do finding."""

from __future__ import annotations

import re
from collections.abc import Iterable

from ...core.domain.entities import Finding
from ...core.domain.value_objects import Category, Confidence, Severity


class _CompiledRule:
    __slots__ = ("rule_id", "pattern", "category", "severity", "confidence", "tags", "description")

    def __init__(self, raw: dict[str, object]) -> None:
        self.rule_id = str(raw.get("id"))
        pattern = str(raw.get("pattern"))
        try:
            self.pattern = re.compile(pattern)
        except re.error as exc:
            raise ValueError(f"Invalid regex in rule {self.rule_id!r}: {exc}") from exc
        self.category = Category.coerce(str(raw.get("category", "OTHER")))
        self.severity = Severity.from_string(str(raw.get("severity", "MEDIUM")))
        self.confidence = Confidence(int(raw.get("confidence", 50)))
        self.tags = set(raw.get("tags") or [])
        self.description = str(raw.get("description", ""))


class RegexDetector:
    def __init__(self, raw_rules: Iterable[dict[str, object]]) -> None:
        self._rules: list[_CompiledRule] = [_CompiledRule(r) for r in raw_rules]

    async def detect(self, finding: Finding) -> Finding:
        haystack = self._haystack(finding)
        highest_severity = finding.severity
        for rule in self._rules:
            matches = rule.pattern.findall(haystack)
            if not matches:
                continue
            samples = [str(m if isinstance(m, str) else m[0])[:80] for m in matches[:5]]
            finding.add_tags(*rule.tags, "rule:regex")
            finding.record_event(
                "rule.matched",
                f"regex rule {rule.rule_id} matched {len(matches)} times",
                {
                    "rule_id": rule.rule_id,
                    "engine": "regex",
                    "match_count": len(matches),
                    "samples": samples,
                    "severity": rule.severity.name,
                    "category": rule.category.value,
                },
            )
            if rule.severity > highest_severity:
                highest_severity = rule.severity
            if finding.category is Category.OTHER:
                finding.category = rule.category
        if highest_severity != finding.severity:
            finding.set_severity(highest_severity, "escalated by regex detection")
        return finding

    @staticmethod
    def _haystack(finding: Finding) -> str:
        return "\n".join(
            [finding.title, finding.description]
            + [str(v) for v in finding.normalized_data.values() if isinstance(v, str)]
        )
