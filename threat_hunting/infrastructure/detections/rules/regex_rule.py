"""Regex detection rule.

Responsibility
--------------
Fire when a configured regular expression matches the finding's normalized
text. The regex is supplied at construction (loaded from config), so no pattern
is hardcoded in the engine.
"""

from __future__ import annotations

import re
from collections.abc import Sequence

from threat_hunting.core.domain.entities.finding import Finding
from threat_hunting.core.domain.value_objects.score import DetectionMatch


class RegexRule:
    """A detection rule backed by a single compiled regular expression."""

    rule_type = "regex"

    def __init__(
        self, rule_id: str, pattern: str, weight: float = 15.0, *, flags: int = re.IGNORECASE
    ) -> None:
        self.rule_id = rule_id
        self.weight = weight
        self._regex = re.compile(pattern, flags)

    def _text(self, finding: Finding) -> str:
        return finding.normalized_data.get("text") or f"{finding.title}\n{finding.description}"

    def evaluate(self, finding: Finding) -> Sequence[DetectionMatch]:
        """Return one match per distinct regex hit in the finding text."""
        matches: list[DetectionMatch] = []
        seen: set[str] = set()
        for hit in self._regex.finditer(self._text(finding)):
            value = hit.group(0)
            if value in seen:
                continue
            seen.add(value)
            matches.append(
                DetectionMatch(
                    rule_id=self.rule_id,
                    rule_type=self.rule_type,
                    matched=value,
                    weight=self.weight,
                )
            )
        return matches
