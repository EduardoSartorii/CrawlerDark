"""Detection rule strategies.

Responsibility
--------------
Provide the concrete detection rules (Strategy pattern) evaluated by the
:class:`DetectionEngine`. Rules are data-driven: each is built from a YAML
definition, so **no rule is ever hardcoded** in the engine. Supported kinds:

* ``regex``   — a regular expression over the finding text.
* ``keyword`` — one or more terms (optionally all-required).
* ``ioc``     — presence of any indicator (optionally of specific types).
* ``actor``   — mentions of a tracked threat-actor name/alias.
* ``yara``    — a YARA rule (evaluated only when ``yara-python`` is installed).
* ``sigma``   — a simplified Sigma keyword match (best-effort, log-context).
* ``composite`` — AND/OR combination of the above (composite rules).

Each rule carries a ``weight`` consumed by the scoring engine, keeping detection
and scoring consistent and configurable.
"""

from __future__ import annotations

import re
from collections.abc import Sequence

from threat_hunting.core.application.ports.rules import DetectionRule

try:  # optional native dependency
    import yara  # type: ignore

    _YARA_AVAILABLE = True
except Exception:  # noqa: BLE001 - yara is optional
    yara = None  # type: ignore
    _YARA_AVAILABLE = False


class RegexRule(DetectionRule):
    """Fires when a regular expression matches the text."""

    kind = "regex"

    def __init__(self, rule_id: str, pattern: str, weight: float, *, flags: int = re.I) -> None:
        self.id = rule_id
        self.weight = weight
        self._regex = re.compile(pattern, flags)

    def evaluate(self, text: str) -> bool:
        return self._regex.search(text) is not None


class KeywordRule(DetectionRule):
    """Fires when configured keyword(s) appear in the text."""

    kind = "keyword"

    def __init__(
        self,
        rule_id: str,
        terms: Sequence[str],
        weight: float,
        *,
        require_all: bool = False,
        case_sensitive: bool = False,
    ) -> None:
        self.id = rule_id
        self.weight = weight
        self._require_all = require_all
        self._case_sensitive = case_sensitive
        self._terms = list(terms) if case_sensitive else [t.lower() for t in terms]

    def evaluate(self, text: str) -> bool:
        haystack = text if self._case_sensitive else text.lower()
        checks = (term in haystack for term in self._terms)
        return all(checks) if self._require_all else any(checks)


class IOCPresenceRule(DetectionRule):
    """Fires when the text contains IOC-like patterns.

    Kept intentionally simple (URL/IP/hash hints); precise typed extraction is
    the extractor's job. This lets an analyst say "flag anything with an IOC".
    """

    kind = "ioc"
    _HINTS = re.compile(
        r"(https?://|\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[a-f0-9]{32,64}\b)", re.I
    )

    def __init__(self, rule_id: str, weight: float) -> None:
        self.id = rule_id
        self.weight = weight

    def evaluate(self, text: str) -> bool:
        return self._HINTS.search(text) is not None


class ThreatActorRule(DetectionRule):
    """Fires when a tracked threat-actor name/alias is mentioned."""

    kind = "actor"

    def __init__(self, rule_id: str, names: Sequence[str], weight: float) -> None:
        self.id = rule_id
        self.weight = weight
        self._names = [n.lower() for n in names]

    def evaluate(self, text: str) -> bool:
        haystack = text.lower()
        return any(name in haystack for name in self._names)


class YaraRule(DetectionRule):
    """Fires when a YARA rule matches (no-op if yara is unavailable)."""

    kind = "yara"

    def __init__(self, rule_id: str, source: str, weight: float) -> None:
        self.id = rule_id
        self.weight = weight
        self._compiled = None
        if _YARA_AVAILABLE:
            try:
                self._compiled = yara.compile(source=source)  # type: ignore[union-attr]
            except Exception:  # noqa: BLE001 - invalid rule shouldn't crash load
                self._compiled = None

    @property
    def available(self) -> bool:
        """Whether this rule can actually evaluate (yara present + compiled)."""
        return self._compiled is not None

    def evaluate(self, text: str) -> bool:
        if self._compiled is None:
            return False
        try:
            return bool(self._compiled.match(data=text.encode("utf-8", "replace")))
        except Exception:  # noqa: BLE001
            return False


class SigmaKeywordRule(DetectionRule):
    """Best-effort Sigma matcher (keyword ``selection`` over text).

    Full Sigma targets structured log events; when applied to unstructured
    collected text the platform evaluates the rule's keyword selection, which is
    the meaningful subset for OSINT/hunting context.
    """

    kind = "sigma"

    def __init__(self, rule_id: str, keywords: Sequence[str], weight: float) -> None:
        self.id = rule_id
        self.weight = weight
        self._keywords = [k.lower() for k in keywords]

    def evaluate(self, text: str) -> bool:
        haystack = text.lower()
        return any(k in haystack for k in self._keywords)


class CompositeRule(DetectionRule):
    """Combines sub-rules with AND/OR logic (composite detection)."""

    kind = "composite"

    def __init__(
        self,
        rule_id: str,
        rules: Sequence[DetectionRule],
        weight: float,
        *,
        operator: str = "and",
    ) -> None:
        self.id = rule_id
        self.weight = weight
        self._rules = list(rules)
        self._operator = operator.lower()

    def evaluate(self, text: str) -> bool:
        results = (rule.evaluate(text) for rule in self._rules)
        return all(results) if self._operator == "and" else any(results)
