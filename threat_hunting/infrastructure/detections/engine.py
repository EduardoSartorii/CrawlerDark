"""Detection engine — dynamic rule loading and application.

Supports regex, keywords, IOC match, threat actor match, heuristics,
whitelist, blacklist, threshold, and composite rules. No hardcoded rules.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

import structlog

from threat_hunting.core.contracts.services import IDetectionEngine
from threat_hunting.core.domain.entities import Finding
from threat_hunting.core.domain.enums import RuleType, Severity

if TYPE_CHECKING:
    from threat_hunting.core.contracts.repositories import IDetectionRuleRepository, IWatchlistRepository

logger = structlog.get_logger(__name__)

SEVERITY_ORDER: dict[str, int] = {
    Severity.INFO.value: 0,
    Severity.LOW.value: 1,
    Severity.MEDIUM.value: 2,
    Severity.HIGH.value: 3,
    Severity.CRITICAL.value: 4,
}


class DetectionEngine(IDetectionEngine):
    """Applies dynamically loaded detection rules to findings."""

    def __init__(
        self,
        rule_repo: IDetectionRuleRepository,
        watchlist_repo: IWatchlistRepository,
    ) -> None:
        self._rule_repo = rule_repo
        self._watchlist_repo = watchlist_repo

    async def detect(self, finding: Finding) -> tuple[Finding, list[str]]:
        rules = await self._rule_repo.list_enabled()
        watchlists = await self._watchlist_repo.list_enabled()
        matched: list[str] = []
        content = f"{finding.title} {finding.description} {finding.normalized_data}"

        for rule in rules:
            if await self._apply_rule(rule, finding, content, watchlists):
                matched.append(rule.name)
                finding.add_tag(f"rule:{rule.name}")
                if SEVERITY_ORDER.get(rule.severity.value, 0) > SEVERITY_ORDER.get(
                    finding.severity.value, 0
                ):
                    finding.severity = rule.severity

        if matched:
            finding.metadata["matched_rules"] = matched
            finding.add_timeline_event("detection", f"Matched rules: {', '.join(matched)}")

        logger.info("detection.completed", finding_id=str(finding.id), matched=len(matched))
        return finding, matched

    async def _apply_rule(self, rule, finding: Finding, content: str, watchlists) -> bool:
        """Apply a single rule using Strategy pattern."""
        rule_type = rule.rule_type

        if rule_type == RuleType.REGEX.value:
            return bool(re.search(rule.pattern, content, re.IGNORECASE))

        if rule_type == RuleType.KEYWORD.value:
            return rule.pattern.lower() in content.lower()

        if rule_type == RuleType.IOC_MATCH.value:
            return any(ind.value.lower() == rule.pattern.lower() for ind in finding.indicators)

        if rule_type == RuleType.THREAT_ACTOR.value:
            return rule.pattern.lower() in content.lower()

        if rule_type == RuleType.WHITELIST.value:
            if rule.pattern.lower() in content.lower():
                finding.metadata["whitelisted"] = True
            return False

        if rule_type == RuleType.BLACKLIST.value:
            return rule.pattern.lower() in content.lower()

        if rule_type == RuleType.HEURISTIC.value:
            return len(finding.indicators) >= int(rule.metadata.get("min_indicators", 3))

        if rule_type == RuleType.THRESHOLD.value:
            return finding.score >= float(rule.metadata.get("threshold", 50))

        if rule_type == RuleType.COMPOSITE.value:
            sub_rules = rule.metadata.get("conditions", [])
            results = []
            for cond in sub_rules:
                results.append(cond.lower() in content.lower())
            operator = rule.metadata.get("operator", "and")
            return all(results) if operator == "and" else any(results)

        # Watchlist-based detection
        for entry in watchlists:
            if entry.enabled and entry.value.lower() in content.lower():
                finding.add_tag(f"watchlist:{entry.watchlist_type}")
                return True

        return False
