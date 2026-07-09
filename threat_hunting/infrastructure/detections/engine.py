"""
Detection Engine.

Evaluates Findings against a library of detection rules.
Rules are loaded dynamically from storage — never hardcoded.

Supported rule types:
    - REGEX: Compiled Python regex patterns
    - YARA: YARA malware detection (requires yara-python)
    - KEYWORD: Simple keyword/substring matching
    - IOC: Direct IOC value comparison against watchlists
    - COMPOSITE: Logical combination (AND/OR) of child rules
    - HEURISTIC: Configurable threshold-based scoring rules

Architecture:
    - Strategy Pattern: each rule type has its own evaluator (RuleEvaluator)
    - The engine dispatches to the appropriate evaluator based on rule type
    - Rules are compiled once at startup and cached for performance
    - Detection results carry the matched rules for auditability

The Detection Engine enriches Findings with:
    - Matched rules list
    - Score contributions per rule
    - New tags based on rule matches
    - Category overrides if rules mandate them
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

import structlog

from ...core.domain.entities.finding import Finding
from ...core.domain.entities.rule import DetectionRule, RuleType
from ...core.domain.value_objects.score import Score

logger = structlog.get_logger(__name__)

# Optional YARA support
try:
    import yara
    _YARA_AVAILABLE = True
except ImportError:
    _YARA_AVAILABLE = False
    logger.warning("detection.yara_unavailable", note="Install yara-python for YARA support")


@dataclass
class RuleMatch:
    """Records a single rule match with its contribution."""

    rule_id: str
    rule_name: str
    rule_type: RuleType
    score_contribution: float
    matched_value: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class DetectionResult:
    """Complete detection result for a single Finding."""

    finding_id: str
    matched_rules: list[RuleMatch] = field(default_factory=list)
    total_score_contribution: float = 0.0
    suppressed: bool = False
    suppression_reason: str = ""
    tags_added: list[str] = field(default_factory=list)

    @property
    def has_matches(self) -> bool:
        return len(self.matched_rules) > 0

    def add_match(self, match: RuleMatch) -> None:
        self.matched_rules.append(match)
        self.total_score_contribution += match.score_contribution


# ─── Rule Evaluators (Strategy Pattern) ───────────────────────────────────────


class RuleEvaluator(ABC):
    """Abstract base for rule type evaluators."""

    @abstractmethod
    def evaluate(self, rule: DetectionRule, finding: Finding) -> RuleMatch | None:
        """Return a RuleMatch if the rule matches, None otherwise."""


class RegexEvaluator(RuleEvaluator):
    """Evaluates REGEX rules against Finding content."""

    def __init__(self) -> None:
        self._cache: dict[str, re.Pattern[str]] = {}

    def _get_pattern(self, rule: DetectionRule) -> re.Pattern[str]:
        if rule.id not in self._cache:
            flags = 0 if rule.metadata.get("case_sensitive") else re.IGNORECASE
            self._cache[rule.id] = re.compile(rule.pattern, flags | re.DOTALL)
        return self._cache[rule.id]

    def evaluate(self, rule: DetectionRule, finding: Finding) -> RuleMatch | None:
        try:
            pattern = self._get_pattern(rule)
            content = self._get_content(finding)
            match = pattern.search(content)
            if match:
                return RuleMatch(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    rule_type=RuleType.REGEX,
                    score_contribution=rule.effective_score_boost,
                    matched_value=match.group(0)[:200],
                )
        except re.error as exc:
            logger.warning("detection.regex_error", rule=rule.name, error=str(exc))
        return None

    def _get_content(self, finding: Finding) -> str:
        return f"{finding.title} {finding.description} {finding.raw_data}"


class KeywordEvaluator(RuleEvaluator):
    """Evaluates KEYWORD rules (simple substring match)."""

    def evaluate(self, rule: DetectionRule, finding: Finding) -> RuleMatch | None:
        content = f"{finding.title} {finding.description} {finding.raw_data}"
        search = rule.pattern if rule.metadata.get("case_sensitive") else rule.pattern.lower()
        haystack = content if rule.metadata.get("case_sensitive") else content.lower()

        if search in haystack:
            return RuleMatch(
                rule_id=rule.id,
                rule_name=rule.name,
                rule_type=RuleType.KEYWORD,
                score_contribution=rule.effective_score_boost,
                matched_value=rule.pattern,
            )
        return None


class IOCEvaluator(RuleEvaluator):
    """Evaluates IOC rules against Finding normalized data and raw content."""

    def evaluate(self, rule: DetectionRule, finding: Finding) -> RuleMatch | None:
        search_value = rule.pattern.lower().strip()
        # Check raw data, title, description
        targets = [
            finding.title.lower(),
            finding.description.lower(),
            finding.raw_data.lower(),
            str(finding.normalized_data).lower(),
        ]
        for target in targets:
            if search_value in target:
                return RuleMatch(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    rule_type=RuleType.IOC,
                    score_contribution=rule.effective_score_boost,
                    matched_value=rule.pattern,
                )
        return None


class YARAEvaluator(RuleEvaluator):
    """Evaluates YARA rules against raw content (requires yara-python)."""

    def __init__(self) -> None:
        self._compiled: dict[str, Any] = {}

    def _compile(self, rule: DetectionRule) -> Any:
        if not _YARA_AVAILABLE:
            return None
        if rule.id not in self._compiled:
            try:
                self._compiled[rule.id] = yara.compile(source=rule.pattern)
            except Exception as exc:
                logger.warning("detection.yara_compile_error", rule=rule.name, error=str(exc))
                self._compiled[rule.id] = None
        return self._compiled[rule.id]

    def evaluate(self, rule: DetectionRule, finding: Finding) -> RuleMatch | None:
        compiled = self._compile(rule)
        if compiled is None:
            return None
        try:
            matches = compiled.match(data=finding.raw_data.encode("utf-8", errors="ignore"))
            if matches:
                return RuleMatch(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    rule_type=RuleType.YARA,
                    score_contribution=rule.effective_score_boost,
                    matched_value=str([m.rule for m in matches]),
                )
        except Exception as exc:
            logger.warning("detection.yara_match_error", rule=rule.name, error=str(exc))
        return None


class HeuristicEvaluator(RuleEvaluator):
    """
    Evaluates threshold-based heuristic rules.

    Pattern format: "field:operator:value"
    Example: "score:gte:5.0" | "ioc_count:gt:3" | "tag:contains:darkweb"
    """

    def evaluate(self, rule: DetectionRule, finding: Finding) -> RuleMatch | None:
        try:
            parts = rule.pattern.split(":", 2)
            if len(parts) != 3:
                return None
            field_name, operator, threshold = parts

            value = self._get_field_value(finding, field_name)
            if value is None:
                return None

            if self._check(value, operator, threshold):
                return RuleMatch(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    rule_type=RuleType.HEURISTIC,
                    score_contribution=rule.effective_score_boost,
                    matched_value=f"{field_name}={value}",
                )
        except Exception as exc:
            logger.warning("detection.heuristic_error", rule=rule.name, error=str(exc))
        return None

    def _get_field_value(self, finding: Finding, field: str) -> Any:
        field_map = {
            "score": finding.score.value,
            "confidence": finding.confidence,
            "ioc_count": finding.ioc_count,
            "tag_count": len(finding.tags),
            "title_length": len(finding.title),
        }
        return field_map.get(field)

    def _check(self, value: Any, operator: str, threshold: str) -> bool:
        t: float = float(threshold)
        v: float = float(value)
        ops = {"gte": v >= t, "gt": v > t, "lte": v <= t, "lt": v < t, "eq": v == t}
        return ops.get(operator, False)


# ─── Detection Engine ──────────────────────────────────────────────────────────


class DetectionEngine:
    """
    Evaluates Findings against the full rule library.

    The engine is the heart of the detection layer:
    - Loads all active rules
    - Dispatches to the appropriate evaluator for each rule type
    - Accumulates match results
    - Applies score contributions and tags to Findings
    - Suppresses findings that match whitelist rules
    """

    def __init__(self, rules: list[DetectionRule] | None = None) -> None:
        self._rules: list[DetectionRule] = rules or []
        self._evaluators: dict[RuleType, RuleEvaluator] = {
            RuleType.REGEX: RegexEvaluator(),
            RuleType.KEYWORD: KeywordEvaluator(),
            RuleType.IOC: IOCEvaluator(),
            RuleType.YARA: YARAEvaluator(),
            RuleType.HEURISTIC: HeuristicEvaluator(),
        }

    def load_rules(self, rules: list[DetectionRule]) -> None:
        """Replace the rule set (called after dynamic reload)."""
        active = [r for r in rules if r.is_active]
        self._rules = sorted(active, key=lambda r: r.priority, reverse=True)
        logger.info("detection.rules_loaded", count=len(self._rules))

    def add_rule(self, rule: DetectionRule) -> None:
        self._rules.append(rule)
        self._rules.sort(key=lambda r: r.priority, reverse=True)

    def evaluate(self, finding: Finding) -> DetectionResult:
        """
        Evaluate all active rules against a Finding.

        Rules are evaluated in priority order.
        Whitelist rules can suppress the finding (zero score, no export).
        """
        result = DetectionResult(finding_id=finding.id)

        for rule in self._rules:
            if not rule.is_active:
                continue
            if not rule.applies_to_connector(finding.connector):
                continue
            if not rule.applies_to_category(finding.category.value):
                continue

            evaluator = self._evaluators.get(rule.rule_type)
            if evaluator is None:
                continue

            match = evaluator.evaluate(rule, finding)
            if match is None:
                continue

            # Handle whitelist rules
            if rule.is_whitelist:
                result.suppressed = True
                result.suppression_reason = f"Matched whitelist rule: {rule.name}"
                logger.debug(
                    "detection.suppressed",
                    finding_id=finding.id,
                    rule=rule.name,
                )
                break

            result.add_match(match)

            # Apply tags from rule
            for tag in rule.tags:
                finding.add_tag(tag)
                result.tags_added.append(tag)

        # Apply score contributions to finding
        if not result.suppressed and result.has_matches:
            new_score = Score(
                value=finding.score.value + result.total_score_contribution,
                confidence=finding.confidence,
            )
            finding.apply_score(new_score)
            logger.debug(
                "detection.scored",
                finding_id=finding.id,
                matches=len(result.matched_rules),
                score_delta=result.total_score_contribution,
                new_score=finding.score.value,
            )

        return result

    def evaluate_batch(self, findings: list[Finding]) -> list[DetectionResult]:
        """Evaluate multiple findings, returning results in the same order."""
        return [self.evaluate(f) for f in findings]
