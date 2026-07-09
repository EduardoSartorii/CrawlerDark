"""Heuristic detection rule.

Responsibility
--------------
Fire on soft signals that are not a single keyword/IOC but a *combination*
suggesting a leak/breach (e.g. the co-occurrence of leak vocabulary with
credential-like tokens). Encapsulates composite/heuristic logic so the engine
stays generic.
"""

from __future__ import annotations

import re
from collections.abc import Sequence

from threat_hunting.core.domain.entities.finding import Finding
from threat_hunting.core.domain.value_objects.score import DetectionMatch

_LEAK_VOCAB = re.compile(
    r"\b(leak|dump|breach|combo|fullz|database|creds?|credentials?|0day|ransom)\b",
    re.IGNORECASE,
)
_CREDENTIAL_PAIR = re.compile(r"[\w.+-]+@[\w.-]+:\S+|[\w.-]{3,}:\S{4,}")


class HeuristicRule:
    """Composite heuristic: leak vocabulary combined with credential patterns."""

    rule_type = "heuristic"

    def __init__(self, rule_id: str = "heuristic.leak_signal", weight: float = 18.0) -> None:
        self.rule_id = rule_id
        self._weight = weight

    def _text(self, finding: Finding) -> str:
        return finding.normalized_data.get("text") or f"{finding.title}\n{finding.description}"

    def evaluate(self, finding: Finding) -> Sequence[DetectionMatch]:
        """Return a match when leak vocabulary and credential pairs co-occur."""
        text = self._text(finding)
        has_vocab = bool(_LEAK_VOCAB.search(text))
        has_creds = bool(_CREDENTIAL_PAIR.search(text))
        if has_vocab and has_creds:
            return [
                DetectionMatch(
                    rule_id=self.rule_id,
                    rule_type=self.rule_type,
                    matched="leak_vocabulary+credential_pattern",
                    weight=self._weight,
                    category="heuristic",
                )
            ]
        return []
