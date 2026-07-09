"""YAML-backed rule and watchlist repositories.

Responsibility
--------------
Load detection rules and hunting watchlists dynamically from configuration
(YAML), implementing :class:`RuleRepositoryPort` and
:class:`WatchlistRepositoryPort`. Because rules are data, an operator (or a
future Django admin) adds/edits detections without touching Python. A rule
**factory** maps each YAML definition to a concrete rule strategy.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from threat_hunting.core.application.ports.rules import (
    DetectionRule,
    RuleRepositoryPort,
    WatchlistRepositoryPort,
)
from threat_hunting.core.domain.watchlist import (
    Brand,
    Campaign,
    Keyword,
    ThreatActor,
    VIP,
    Watchlist,
)
from threat_hunting.infrastructure.detections.rules import (
    CompositeRule,
    IOCPresenceRule,
    KeywordRule,
    RegexRule,
    SigmaKeywordRule,
    ThreatActorRule,
    YaraRule,
)


def build_rule(spec: dict[str, Any]) -> DetectionRule | None:
    """Instantiate a detection rule from a YAML/dict specification.

    Returns ``None`` for disabled or unknown rule kinds so a single bad entry
    never breaks the whole rule set.
    """
    if not spec.get("enabled", True):
        return None
    kind = str(spec.get("kind", "")).lower()
    rule_id = str(spec.get("id", kind))
    weight = float(spec.get("weight", 10.0))

    if kind == "regex":
        return RegexRule(rule_id, spec["pattern"], weight)
    if kind == "keyword":
        return KeywordRule(
            rule_id,
            spec.get("terms", []),
            weight,
            require_all=bool(spec.get("require_all", False)),
            case_sensitive=bool(spec.get("case_sensitive", False)),
        )
    if kind == "ioc":
        return IOCPresenceRule(rule_id, weight)
    if kind == "actor":
        return ThreatActorRule(rule_id, spec.get("names", []), weight)
    if kind == "yara":
        return YaraRule(rule_id, spec.get("source", ""), weight)
    if kind == "sigma":
        return SigmaKeywordRule(rule_id, spec.get("keywords", []), weight)
    if kind == "composite":
        sub = [r for r in (build_rule(s) for s in spec.get("rules", [])) if r]
        return CompositeRule(
            rule_id, sub, weight, operator=str(spec.get("operator", "and"))
        )
    return None


class YamlRuleRepository(RuleRepositoryPort):
    """Loads all ``*.yml`` rule files from a directory."""

    def __init__(self, rules_dir: str | Path) -> None:
        self._dir = Path(rules_dir)

    def load(self) -> list[DetectionRule]:
        """Return every enabled rule found under the rules directory."""
        rules: list[DetectionRule] = []
        if not self._dir.exists():
            return rules
        for path in sorted(self._dir.glob("*.y*ml")):
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            for spec in data.get("rules", []):
                rule = build_rule(spec)
                if rule is not None:
                    rules.append(rule)
        return rules


class YamlWatchlistRepository(WatchlistRepositoryPort):
    """Loads watchlists (keywords, VIPs, brands, actors, campaigns) from YAML."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)

    def load(self) -> list[Watchlist]:
        """Return every enabled watchlist declared in the YAML file."""
        if not self._path.exists():
            return []
        data = yaml.safe_load(self._path.read_text(encoding="utf-8")) or {}
        watchlists: list[Watchlist] = []
        for spec in data.get("watchlists", []):
            watchlists.append(
                Watchlist(
                    name=spec["name"],
                    category=spec.get("category", "threat_hunting"),
                    base_weight=float(spec.get("base_weight", 1.0)),
                    keywords=[self._keyword(k) for k in spec.get("keywords", [])],
                    vips=[VIP(**v) for v in spec.get("vips", [])],
                    brands=[Brand(**b) for b in spec.get("brands", [])],
                    actors=[ThreatActor(**a) for a in spec.get("actors", [])],
                    campaigns=[Campaign(**c) for c in spec.get("campaigns", [])],
                )
            )
        return watchlists

    @staticmethod
    def _keyword(spec: dict[str, Any] | str) -> Keyword:
        """Accept a bare string or a full keyword mapping."""
        if isinstance(spec, str):
            return Keyword(term=spec)
        return Keyword(**spec)
