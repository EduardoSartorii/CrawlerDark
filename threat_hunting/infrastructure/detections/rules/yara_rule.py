"""YARA detection rule.

Responsibility
--------------
Match finding content (and artifact bodies, when available) against compiled
YARA rules. ``yara-python`` is an optional dependency: when it is not installed
the rule degrades to a safe no-op so the rest of the detection engine keeps
working. This keeps the platform functional in minimal environments while
supporting full YARA where the library is present.
"""

from __future__ import annotations

from collections.abc import Sequence

from threat_hunting.core.domain.entities.finding import Finding
from threat_hunting.core.domain.value_objects.score import DetectionMatch


class YaraRule:
    """Applies a compiled YARA ruleset to finding text (optional dependency)."""

    rule_type = "yara"

    def __init__(self, rule_id: str, source: str, weight: float = 22.0) -> None:
        self.rule_id = rule_id
        self.weight = weight
        self._source = source
        self._compiled = self._compile(source)

    @staticmethod
    def _compile(source: str) -> object | None:
        """Compile the YARA source, returning ``None`` when yara is unavailable."""
        try:
            import yara  # optional dependency
        except ImportError:
            return None
        try:
            return yara.compile(source=source)
        except Exception:
            return None

    @property
    def available(self) -> bool:
        """Whether a compiled ruleset is active (yara installed + valid source)."""
        return self._compiled is not None

    def _text(self, finding: Finding) -> str:
        return finding.normalized_data.get("text") or f"{finding.title}\n{finding.description}"

    def evaluate(self, finding: Finding) -> Sequence[DetectionMatch]:
        """Return a match per YARA rule that hits the finding text."""
        if self._compiled is None:
            return []
        try:
            hits = self._compiled.match(data=self._text(finding))  # type: ignore[attr-defined]
        except Exception:
            return []
        return [
            DetectionMatch(
                rule_id=f"{self.rule_id}:{getattr(hit, 'rule', 'yara')}",
                rule_type=self.rule_type,
                matched=str(getattr(hit, "rule", "yara")),
                weight=self.weight,
                category="yara",
            )
            for hit in hits
        ]
