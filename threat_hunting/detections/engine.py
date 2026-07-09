"""Detection Engine — Strategy Pattern + dynamic rule loading.

Responsibility
--------------
Evaluate Findings against dynamically loaded rules (regex, keyword, IOC,
threat actor, heuristics, whitelist/blacklist, threshold, composite).
NO rules are hardcoded — all loaded from config/detection/*.yaml.
YARA/Sigma adapters are pluggable strategies.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

import structlog
import yaml

from threat_hunting.core.application.ports import DetectionEnginePort
from threat_hunting.core.domain.entities import Finding
from threat_hunting.core.domain.enums import DetectionRuleType, Severity
from threat_hunting.core.domain.value_objects import DetectionMatch

logger = structlog.get_logger(__name__)


class DetectionStrategy(ABC):
    """Strategy interface for a single detection rule type."""

    rule_type: DetectionRuleType

    @abstractmethod
    def evaluate(self, finding: Finding, rule: dict[str, Any]) -> DetectionMatch:
        """Evaluate one rule against a Finding."""


class RegexStrategy(DetectionStrategy):
    rule_type = DetectionRuleType.REGEX

    def evaluate(self, finding: Finding, rule: dict[str, Any]) -> DetectionMatch:
        pattern = rule["pattern"]
        flags = re.IGNORECASE if rule.get("ignore_case", True) else 0
        text = f"{finding.title}\n{finding.description}\n{finding.raw_data}"
        matches = re.findall(pattern, text, flags)
        matched_values = [m if isinstance(m, str) else m[0] for m in matches] if matches else []
        return DetectionMatch(
            rule_id=rule["id"],
            rule_type=self.rule_type.value,
            matched=bool(matched_values),
            matched_values=matched_values[:50],
            severity=Severity(rule.get("severity", "medium")),
            score_delta=float(rule.get("score_delta", 10.0)) if matched_values else 0.0,
            details={"pattern": pattern},
        )


class KeywordStrategy(DetectionStrategy):
    rule_type = DetectionRuleType.KEYWORD

    def evaluate(self, finding: Finding, rule: dict[str, Any]) -> DetectionMatch:
        keywords = rule.get("keywords", [])
        case_sensitive = rule.get("case_sensitive", False)
        text = f"{finding.title} {finding.description}"
        haystack = text if case_sensitive else text.lower()
        matched = []
        for kw in keywords:
            needle = kw if case_sensitive else kw.lower()
            if needle in haystack:
                matched.append(kw)
        return DetectionMatch(
            rule_id=rule["id"],
            rule_type=self.rule_type.value,
            matched=bool(matched),
            matched_values=matched,
            severity=Severity(rule.get("severity", "low")),
            score_delta=float(rule.get("score_delta", 5.0)) * len(matched) if matched else 0.0,
        )


class IocMatchStrategy(DetectionStrategy):
    rule_type = DetectionRuleType.IOC_MATCH

    def evaluate(self, finding: Finding, rule: dict[str, Any]) -> DetectionMatch:
        iocs = {v.lower() for v in rule.get("iocs", [])}
        matched = [i.value for i in finding.indicators if i.value.lower() in iocs]
        # Also scan text
        text = f"{finding.title} {finding.description}".lower()
        for ioc in iocs:
            if ioc in text and ioc not in {m.lower() for m in matched}:
                matched.append(ioc)
        return DetectionMatch(
            rule_id=rule["id"],
            rule_type=self.rule_type.value,
            matched=bool(matched),
            matched_values=matched,
            severity=Severity(rule.get("severity", "high")),
            score_delta=float(rule.get("score_delta", 20.0)) if matched else 0.0,
        )


class ThreatActorMatchStrategy(DetectionStrategy):
    rule_type = DetectionRuleType.THREAT_ACTOR_MATCH

    def evaluate(self, finding: Finding, rule: dict[str, Any]) -> DetectionMatch:
        actors = rule.get("actors", [])
        text = f"{finding.title} {finding.description}".lower()
        matched = [a for a in actors if a.lower() in text]
        return DetectionMatch(
            rule_id=rule["id"],
            rule_type=self.rule_type.value,
            matched=bool(matched),
            matched_values=matched,
            severity=Severity(rule.get("severity", "high")),
            score_delta=float(rule.get("score_delta", 25.0)) if matched else 0.0,
        )


class HeuristicStrategy(DetectionStrategy):
    rule_type = DetectionRuleType.HEURISTIC

    def evaluate(self, finding: Finding, rule: dict[str, Any]) -> DetectionMatch:
        """Simple heuristic: credential/card/leak keyword density."""
        signals = rule.get("signals", ["password", "leak", "dump", "credential", "cvv"])
        text = f"{finding.title} {finding.description}".lower()
        matched = [s for s in signals if s in text]
        threshold = int(rule.get("min_signals", 1))
        hit = len(matched) >= threshold
        return DetectionMatch(
            rule_id=rule["id"],
            rule_type=self.rule_type.value,
            matched=hit,
            matched_values=matched,
            severity=Severity(rule.get("severity", "medium")),
            score_delta=float(rule.get("score_delta", 8.0)) * len(matched) if hit else 0.0,
        )


class WhitelistStrategy(DetectionStrategy):
    rule_type = DetectionRuleType.WHITELIST

    def evaluate(self, finding: Finding, rule: dict[str, Any]) -> DetectionMatch:
        entries = [e.lower() for e in rule.get("entries", [])]
        text = f"{finding.title} {finding.description}".lower()
        matched = [e for e in entries if e in text]
        # Whitelist match REDUCES score
        return DetectionMatch(
            rule_id=rule["id"],
            rule_type=self.rule_type.value,
            matched=bool(matched),
            matched_values=matched,
            severity=Severity.INFORMATIONAL,
            score_delta=-abs(float(rule.get("score_delta", 15.0))) if matched else 0.0,
            details={"action": "whitelist_suppress"},
        )


class BlacklistStrategy(DetectionStrategy):
    rule_type = DetectionRuleType.BLACKLIST

    def evaluate(self, finding: Finding, rule: dict[str, Any]) -> DetectionMatch:
        entries = [e.lower() for e in rule.get("entries", [])]
        text = f"{finding.title} {finding.description}".lower()
        matched = [e for e in entries if e in text]
        return DetectionMatch(
            rule_id=rule["id"],
            rule_type=self.rule_type.value,
            matched=bool(matched),
            matched_values=matched,
            severity=Severity(rule.get("severity", "critical")),
            score_delta=float(rule.get("score_delta", 30.0)) if matched else 0.0,
        )


class ThresholdStrategy(DetectionStrategy):
    rule_type = DetectionRuleType.THRESHOLD

    def evaluate(self, finding: Finding, rule: dict[str, Any]) -> DetectionMatch:
        min_iocs = int(rule.get("min_indicators", 3))
        count = len(finding.indicators)
        hit = count >= min_iocs
        return DetectionMatch(
            rule_id=rule["id"],
            rule_type=self.rule_type.value,
            matched=hit,
            matched_values=[str(count)],
            severity=Severity(rule.get("severity", "medium")),
            score_delta=float(rule.get("score_delta", 10.0)) if hit else 0.0,
        )


class YaraStrategy(DetectionStrategy):
    """YARA strategy — uses pattern fallback when yara-python unavailable."""

    rule_type = DetectionRuleType.YARA

    def evaluate(self, finding: Finding, rule: dict[str, Any]) -> DetectionMatch:
        # Portable fallback: treat `strings` as substring matches
        strings = rule.get("strings", [])
        text = f"{finding.title}\n{finding.description}\n{finding.raw_data}"
        matched = [s for s in strings if s in text]
        return DetectionMatch(
            rule_id=rule["id"],
            rule_type=self.rule_type.value,
            matched=bool(matched),
            matched_values=matched,
            severity=Severity(rule.get("severity", "high")),
            score_delta=float(rule.get("score_delta", 20.0)) if matched else 0.0,
            details={"engine": "yara_fallback"},
        )


class SigmaStrategy(DetectionStrategy):
    """Sigma strategy — keyword/field matching adapted to text findings."""

    rule_type = DetectionRuleType.SIGMA

    def evaluate(self, finding: Finding, rule: dict[str, Any]) -> DetectionMatch:
        selection = rule.get("detection", {}).get("selection", {})
        text = f"{finding.title} {finding.description}".lower()
        matched = []
        for _field, values in selection.items():
            vals = values if isinstance(values, list) else [values]
            for v in vals:
                if str(v).lower() in text:
                    matched.append(str(v))
        return DetectionMatch(
            rule_id=rule["id"],
            rule_type=self.rule_type.value,
            matched=bool(matched),
            matched_values=matched,
            severity=Severity(rule.get("severity", "medium")),
            score_delta=float(rule.get("score_delta", 12.0)) if matched else 0.0,
            details={"engine": "sigma_adapted"},
        )


class CompositeStrategy(DetectionStrategy):
    """Composite rule — all/any child rule ids must have matched previously."""

    rule_type = DetectionRuleType.COMPOSITE

    def evaluate(self, finding: Finding, rule: dict[str, Any]) -> DetectionMatch:
        required = set(rule.get("require_rules", []))
        mode = rule.get("mode", "all")  # all | any
        matched_ids = {d.rule_id for d in finding.detections if d.matched}
        if mode == "any":
            hit = bool(required & matched_ids)
        else:
            hit = required.issubset(matched_ids)
        return DetectionMatch(
            rule_id=rule["id"],
            rule_type=self.rule_type.value,
            matched=hit,
            matched_values=list(required & matched_ids),
            severity=Severity(rule.get("severity", "high")),
            score_delta=float(rule.get("score_delta", 15.0)) if hit else 0.0,
        )


STRATEGY_REGISTRY: dict[DetectionRuleType, type[DetectionStrategy]] = {
    DetectionRuleType.REGEX: RegexStrategy,
    DetectionRuleType.KEYWORD: KeywordStrategy,
    DetectionRuleType.IOC_MATCH: IocMatchStrategy,
    DetectionRuleType.THREAT_ACTOR_MATCH: ThreatActorMatchStrategy,
    DetectionRuleType.HEURISTIC: HeuristicStrategy,
    DetectionRuleType.WHITELIST: WhitelistStrategy,
    DetectionRuleType.BLACKLIST: BlacklistStrategy,
    DetectionRuleType.THRESHOLD: ThresholdStrategy,
    DetectionRuleType.YARA: YaraStrategy,
    DetectionRuleType.SIGMA: SigmaStrategy,
    DetectionRuleType.COMPOSITE: CompositeStrategy,
}


class RuleLoader:
    """Load detection rules from YAML files (no hardcoded rules)."""

    def __init__(self, config_dir: Path | str) -> None:
        self._config_dir = Path(config_dir)
        self._rules: list[dict[str, Any]] = []

    def load(self) -> list[dict[str, Any]]:
        self._rules = []
        if not self._config_dir.exists():
            logger.warning("detection.config_missing", path=str(self._config_dir))
            return self._rules
        for path in sorted(self._config_dir.glob("**/*.{yml,yaml}".replace("{yml,yaml}", "yml"))):
            self._load_file(path)
        for path in sorted(self._config_dir.glob("**/*.yaml")):
            self._load_file(path)
        # Deduplicate by path
        seen: set[str] = set()
        unique: list[dict[str, Any]] = []
        for r in self._rules:
            key = r.get("id", id(r))
            if key not in seen:
                seen.add(key)
                unique.append(r)
        self._rules = unique
        logger.info("detection.rules_loaded", count=len(self._rules))
        return self._rules

    def _load_file(self, path: Path) -> None:
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            rules = data if isinstance(data, list) else data.get("rules", [data] if "id" in data else [])
            for rule in rules:
                if isinstance(rule, dict) and "id" in rule and "type" in rule:
                    self._rules.append(rule)
        except Exception as exc:
            logger.error("detection.rule_load_error", path=str(path), error=str(exc))

    @property
    def rules(self) -> list[dict[str, Any]]:
        return self._rules


class DetectionEngine(DetectionEnginePort):
    """Detection Engine implementation — Strategy registry + RuleLoader."""

    def __init__(self, config_dir: Path | str) -> None:
        self._loader = RuleLoader(config_dir)
        self._strategies: dict[DetectionRuleType, DetectionStrategy] = {
            rt: cls() for rt, cls in STRATEGY_REGISTRY.items()
        }
        self._rules: list[dict[str, Any]] = []
        self._loader.load()
        self._rules = self._loader.rules

    async def detect(self, finding: Finding) -> list[DetectionMatch]:
        results: list[DetectionMatch] = []
        # Non-composite first, then composite
        ordered = sorted(
            self._rules,
            key=lambda r: 1 if r.get("type") == DetectionRuleType.COMPOSITE.value else 0,
        )
        # Work on a copy of prior detections so composite can see in-flight matches
        prior = list(finding.detections)
        for rule in ordered:
            try:
                rule_type = DetectionRuleType(rule["type"])
            except ValueError:
                logger.warning(
                    "detection.unknown_rule_type",
                    rule_id=rule.get("id"),
                    type=rule.get("type"),
                )
                continue
            if not rule.get("enabled", True):
                continue
            strategy = self._strategies.get(rule_type)
            if strategy is None:
                continue
            if rule_type == DetectionRuleType.COMPOSITE:
                original = finding.detections
                finding.detections = prior + results
                try:
                    match = strategy.evaluate(finding, rule)
                finally:
                    finding.detections = original
            else:
                match = strategy.evaluate(finding, rule)
            results.append(match)
        return results

    async def reload_rules(self) -> int:
        self._loader.load()
        self._rules = self._loader.rules
        return len(self._rules)


__all__ = [
    "DetectionStrategy",
    "DetectionEngine",
    "RuleLoader",
    "STRATEGY_REGISTRY",
]
