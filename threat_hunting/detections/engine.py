"""Dynamic detection engine.

Rules are loaded from configuration and never hardcoded in core logic.
"""

from __future__ import annotations

import re
from typing import Any

from threat_hunting.core.contracts import StageContext
from threat_hunting.domain.entities import DetectionRule, RuleType, WatchlistProfile


class DynamicDetectionEngine:
    """Detection engine supporting regex/keyword/ioc/actor/threshold rules."""

    def __init__(self, rules: list[DetectionRule], watchlist: WatchlistProfile) -> None:
        self._rules = [rule for rule in rules if rule.enabled]
        self._watchlist = watchlist

    def run(self, items: list[dict[str, Any]], context: StageContext) -> list[dict[str, Any]]:
        """Evaluate findings against dynamic rules and return annotated records."""
        output: list[dict[str, Any]] = []
        for item in items:
            matched_rules: list[str] = []
            signals: list[str] = list(item.get("signals", []))
            if self._is_whitelisted(item):
                output.append({**item, "matched_rules": matched_rules, "signals": ["whitelist"], "blocked": True})
                continue
            for rule in self._rules:
                if self._match_rule(rule, item):
                    matched_rules.append(rule.id)
                    signals.append(f"{rule.type.value}_match")
                    for tag in rule.tags:
                        if tag not in item.get("tags", []):
                            item.setdefault("tags", []).append(tag)
            blocked = self._is_blacklisted(item)
            output.append({**item, "matched_rules": matched_rules, "signals": signals, "blocked": blocked})
        return output

    def _is_whitelisted(self, item: dict[str, Any]) -> bool:
        text = self._item_text(item)
        return any(word.lower() in text for word in self._watchlist.watchlists)

    def _is_blacklisted(self, item: dict[str, Any]) -> bool:
        text = self._item_text(item)
        return any(word.lower() in text for word in self._watchlist.threat_actors)

    def _item_text(self, item: dict[str, Any]) -> str:
        return f"{item.get('title', '')} {item.get('description', '')}".lower()

    def _match_rule(self, rule: DetectionRule, item: dict[str, Any]) -> bool:
        text = self._item_text(item)
        normalized = item.get("normalized_data", {})
        indicators = item.get("indicators", [])
        if rule.type == RuleType.regex and rule.pattern:
            return bool(re.search(rule.pattern, text, flags=re.IGNORECASE))
        if rule.type == RuleType.keyword and rule.pattern:
            return rule.pattern.lower() in text
        if rule.type == RuleType.ioc_match:
            ioc_values = {str(i.get("value", "")).lower() for i in indicators if isinstance(i, dict)}
            return any(ioc.lower() in ioc_values for ioc in self._watchlist.ioc_lists)
        if rule.type == RuleType.threat_actor_match:
            actor = str(normalized.get("threat_actor", "")).lower()
            return actor in {value.lower() for value in self._watchlist.threat_actors}
        if rule.type == RuleType.threshold:
            minimum = float(rule.metadata.get("minimum_indicators", 1))
            return len(indicators) >= minimum
        if rule.type in {RuleType.yara, RuleType.sigma, RuleType.composite}:
            patterns = rule.metadata.get("patterns", [])
            return any(str(pattern).lower() in text for pattern in patterns)
        if rule.type == RuleType.blacklist and rule.pattern:
            return rule.pattern.lower() in text
        if rule.type == RuleType.whitelist and rule.pattern:
            return rule.pattern.lower() in text
        return False
