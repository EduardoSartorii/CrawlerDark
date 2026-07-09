"""Threat-actor detection rule.

Responsibility
--------------
Fire when a monitored threat actor's name or alias appears in the finding text,
tagging the finding accordingly. This drives attribution and later correlation
(``attributed_to`` relationships).
"""

from __future__ import annotations

from collections.abc import Sequence

from threat_hunting.core.domain.entities.finding import Finding
from threat_hunting.core.domain.entities.threat_actor import ThreatActor
from threat_hunting.core.domain.value_objects.score import DetectionMatch


class ThreatActorRule:
    """Matches finding text against monitored threat actor terms."""

    rule_type = "threat_actor"

    def __init__(
        self, rule_id: str, actors: Sequence[ThreatActor], weight: float = 20.0
    ) -> None:
        self.rule_id = rule_id
        self._actors = list(actors)
        self._weight = weight

    def _text_lower(self, finding: Finding) -> str:
        return finding.normalized_data.get("text_lower") or (
            f"{finding.title}\n{finding.description}".lower()
        )

    def evaluate(self, finding: Finding) -> Sequence[DetectionMatch]:
        """Return a match per actor whose name/alias appears in the text."""
        text = self._text_lower(finding)
        matches: list[DetectionMatch] = []
        for actor in self._actors:
            for term in actor.match_terms:
                if term and term in text:
                    matches.append(
                        DetectionMatch(
                            rule_id=f"{self.rule_id}:{actor.name}",
                            rule_type=self.rule_type,
                            matched=actor.name,
                            weight=self._weight,
                            category="threat_actor",
                        )
                    )
                    break  # one match per actor is enough
        return matches
