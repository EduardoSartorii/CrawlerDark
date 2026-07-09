"""DetectionEngine.

Responsibility
--------------
Apply a set of :class:`DetectionRule` strategies to a finding and collect the
resulting :class:`DetectionMatch`es, honouring:

* **whitelist** — terms that, when present, suppress *all* detections for the
  finding (known-benign noise);
* **blacklist** — terms that immediately flag the finding;
* **threshold** — the minimum number of matches required for the finding to be
  considered "detected" (composite-rule behaviour).

The engine is agnostic to *which* rules it runs — rules are injected (loaded
dynamically), satisfying "no rule hardcoded".
"""

from __future__ import annotations

from collections.abc import Sequence

from threat_hunting.core.application.ports.detection import DetectionRule
from threat_hunting.core.domain.entities.finding import Finding
from threat_hunting.core.domain.value_objects.score import DetectionMatch


class DetectionEngine:
    """Runs detection rules against findings with whitelist/blacklist/threshold."""

    def __init__(
        self,
        rules: Sequence[DetectionRule],
        *,
        whitelist: Sequence[str] = (),
        blacklist: Sequence[str] = (),
        min_matches: int = 1,
    ) -> None:
        self._rules = list(rules)
        self._whitelist = [w.lower() for w in whitelist]
        self._blacklist = [b.lower() for b in blacklist]
        self._min_matches = max(1, min_matches)

    def _text_lower(self, finding: Finding) -> str:
        return finding.normalized_data.get("text_lower") or (
            f"{finding.title}\n{finding.description}".lower()
        )

    def evaluate(self, finding: Finding) -> list[DetectionMatch]:
        """Evaluate all rules and attach qualifying matches to the finding.

        Returns the list of matches recorded on the finding. When the number of
        matches is below ``min_matches`` (and no blacklist hit), no matches are
        recorded and an empty list is returned.
        """
        text_lower = self._text_lower(finding)

        if any(term in text_lower for term in self._whitelist):
            finding.add_tag("whitelisted")
            finding.record("detection", "suppressed by whitelist")
            return []

        matches: list[DetectionMatch] = []
        for rule in self._rules:
            matches.extend(rule.evaluate(finding))

        blacklist_hits = [term for term in self._blacklist if term in text_lower]
        for term in blacklist_hits:
            matches.append(
                DetectionMatch(
                    rule_id="blacklist",
                    rule_type="blacklist",
                    matched=term,
                    weight=30.0,
                    category="blacklist",
                )
            )

        if not blacklist_hits and len(matches) < self._min_matches:
            finding.record("detection", f"below threshold ({len(matches)}/{self._min_matches})")
            return []

        for match in matches:
            finding.add_detection(match)
        if matches:
            finding.add_tag("detected")
            finding.record("detection", f"{len(matches)} match(es)")
        return matches
