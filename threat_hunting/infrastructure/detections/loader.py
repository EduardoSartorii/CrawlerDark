"""RuleLoader.

Responsibility
--------------
Build detection rules *dynamically* from configuration and the keyword provider,
so nothing is hardcoded in the engine. It assembles:

* regex rules from ``config`` (id → pattern/weight);
* a keyword rule from the provider's watchlists;
* a threat-actor rule from the provider's actors;
* the IOC-presence and heuristic rules;
* optional YARA rules from inline sources.

This is the composition point (Factory) between config data and the Strategy
objects the engine consumes.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from threat_hunting.core.application.ports.detection import DetectionRule
from threat_hunting.core.application.ports.keyword_provider import KeywordProvider
from threat_hunting.infrastructure.detections.rules import (
    HeuristicRule,
    IocMatchRule,
    KeywordRule,
    RegexRule,
    ThreatActorRule,
    YaraRule,
)


class RuleLoader:
    """Assembles detection rule strategies from config + keyword provider."""

    def __init__(self, keyword_provider: KeywordProvider) -> None:
        self._keywords = keyword_provider

    def load(
        self,
        regex_rules: Mapping[str, Mapping[str, object]] | None = None,
        yara_rules: Mapping[str, str] | None = None,
    ) -> Sequence[DetectionRule]:
        """Return the ordered list of detection rules to run."""
        rules: list[DetectionRule] = []

        for rule_id, spec in (regex_rules or {}).items():
            pattern = str(spec.get("pattern", ""))
            if not pattern:
                continue
            weight = float(spec.get("weight", 15.0))
            rules.append(RegexRule(rule_id=rule_id, pattern=pattern, weight=weight))

        watchlists = list(self._keywords.watchlists())
        if watchlists:
            rules.append(KeywordRule(rule_id="watchlist", watchlists=watchlists))

        actors = list(self._keywords.threat_actors())
        if actors:
            rules.append(ThreatActorRule(rule_id="actor", actors=actors))

        rules.append(IocMatchRule())
        rules.append(HeuristicRule())

        for rule_id, source in (yara_rules or {}).items():
            rules.append(YaraRule(rule_id=rule_id, source=source))

        return rules
