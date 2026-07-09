"""Keyword / watchlist detection rule.

Responsibility
--------------
Fire when any keyword from the supplied watchlists appears in the finding text.
Each keyword carries its own weight and case sensitivity (from
:class:`~threat_hunting.core.domain.entities.watchlist.Keyword`), so VIP/brand
terms can weigh more than generic ones — all driven by data, never hardcoded.
"""

from __future__ import annotations

from collections.abc import Sequence

from threat_hunting.core.domain.entities.finding import Finding
from threat_hunting.core.domain.entities.watchlist import Watchlist
from threat_hunting.core.domain.value_objects.score import DetectionMatch


class KeywordRule:
    """Matches finding text against every keyword in the given watchlists."""

    rule_type = "keyword"

    def __init__(self, rule_id: str, watchlists: Sequence[Watchlist]) -> None:
        self.rule_id = rule_id
        self._watchlists = list(watchlists)

    def _text(self, finding: Finding) -> str:
        return finding.normalized_data.get("text") or f"{finding.title}\n{finding.description}"

    def evaluate(self, finding: Finding) -> Sequence[DetectionMatch]:
        """Return a match per keyword that appears in the finding text."""
        text = self._text(finding)
        matches: list[DetectionMatch] = []
        for watchlist in self._watchlists:
            for keyword in watchlist.enabled_keywords():
                if keyword.matches(text):
                    matches.append(
                        DetectionMatch(
                            rule_id=f"{self.rule_id}:{watchlist.name}",
                            rule_type=self.rule_type,
                            matched=keyword.term,
                            weight=keyword.weight,
                            category=keyword.type.value,
                        )
                    )
        return matches
