"""The detection engine.

Responsibility
--------------
Implement :class:`DetectionEnginePort`. It evaluates each finding against the
dynamically loaded rule set *and* the active watchlists (keywords, VIPs, brands,
threat actors, campaigns), applying whitelist/blacklist filters and a minimum
match threshold. It records *what* matched (rule ids, matched targets and their
weights) into ``finding.metadata['detection']`` so the scoring engine can build
an explainable score and analysts can audit every decision.

Business rules
--------------
* Whitelist hit -> finding is suppressed (no match), regardless of other rules.
* Blacklist hit -> forced match with a strong weight.
* A finding matches when its accumulated match count meets ``min_matches``.
* Nothing is hardcoded: rules and watchlists are injected.
"""

from __future__ import annotations

import re
from collections.abc import Sequence

from threat_hunting.core.application.ports.pipeline_stages import DetectionEnginePort
from threat_hunting.core.application.ports.rules import DetectionRule
from threat_hunting.core.domain.entities import Finding
from threat_hunting.core.domain.watchlist import Watchlist


class DetectionEngine(DetectionEnginePort):
    """Evaluates findings against rules and watchlists."""

    def __init__(
        self,
        *,
        rules: Sequence[DetectionRule],
        watchlists: Sequence[Watchlist] | None = None,
        whitelist: Sequence[str] | None = None,
        blacklist: Sequence[str] | None = None,
        min_matches: int = 1,
    ) -> None:
        self._rules = list(rules)
        self._watchlists = list(watchlists or [])
        self._whitelist = [re.compile(p, re.I) for p in (whitelist or [])]
        self._blacklist = [re.compile(p, re.I) for p in (blacklist or [])]
        self._min_matches = max(1, min_matches)

    def detect(self, finding: Finding) -> Finding:
        """Populate ``finding.metadata['detection']`` with all matches."""
        text = self._text(finding)
        detection: dict[str, object] = {
            "rules": [],
            "keywords": [],
            "vips": [],
            "brands": [],
            "actors": [],
            "campaigns": [],
            "weight": 0.0,
            "whitelisted": False,
            "blacklisted": False,
        }

        if any(p.search(text) for p in self._whitelist):
            detection["whitelisted"] = True
            finding.metadata["detection"] = detection
            finding.record("detection", "suppressed by whitelist")
            return finding

        weight = 0.0
        for rule in self._rules:
            if rule.evaluate(text):
                detection["rules"].append({"id": rule.id, "kind": rule.kind})
                weight += rule.weight
                finding.add_tag(f"rule:{rule.id}")

        weight += self._match_watchlists(text, finding, detection)

        if any(p.search(text) for p in self._blacklist):
            detection["blacklisted"] = True
            weight += 50.0
            finding.add_tag("blacklist")

        detection["weight"] = round(weight, 2)
        detection["match_count"] = (
            len(detection["rules"])
            + len(detection["keywords"])
            + len(detection["vips"])
            + len(detection["brands"])
            + len(detection["actors"])
            + len(detection["campaigns"])
            + (1 if detection["blacklisted"] else 0)
        )
        finding.metadata["detection"] = detection
        finding.record(
            "detection",
            f"{detection['match_count']} match(es), weight {detection['weight']}",
        )
        return finding

    def matches(self, finding: Finding) -> bool:
        """Whether the finding met the detection threshold (and not whitelisted)."""
        detection = finding.metadata.get("detection", {})
        if detection.get("whitelisted"):
            return False
        return int(detection.get("match_count", 0)) >= self._min_matches

    # -- internals ---------------------------------------------------------

    def _match_watchlists(
        self, text: str, finding: Finding, detection: dict[str, object]
    ) -> float:
        """Match watchlist targets and accumulate their weights."""
        haystack = text.lower()
        weight = 0.0
        for wl in self._watchlists:
            if not wl.enabled:
                continue
            for kw in wl.active_keywords():
                if self._keyword_hit(kw.term, kw.is_regex, kw.case_sensitive, text, haystack):
                    detection["keywords"].append(kw.term)
                    weight += kw.weight * wl.base_weight
                    finding.add_tag(f"kw:{kw.term}")
            for vip in wl.vips:
                names = [vip.name, *vip.aliases, *vip.emails]
                if any(n.lower() in haystack for n in names if n):
                    detection["vips"].append(vip.name)
                    weight += vip.weight * wl.base_weight
                    finding.add_tag(f"vip:{vip.name}")
            for brand in wl.brands:
                terms = [brand.name, *brand.domains, *brand.keywords]
                if any(t.lower() in haystack for t in terms if t):
                    detection["brands"].append(brand.name)
                    weight += brand.weight * wl.base_weight
                    finding.add_tag(f"brand:{brand.name}")
            for actor in wl.actors:
                names = [actor.name, *actor.aliases]
                if any(n.lower() in haystack for n in names if n):
                    detection["actors"].append(actor.name)
                    weight += actor.weight * wl.base_weight
                    finding.add_tag(f"actor:{actor.name}")
            for campaign in wl.campaigns:
                names = [campaign.name, *campaign.aliases]
                if any(n.lower() in haystack for n in names if n):
                    detection["campaigns"].append(campaign.name)
                    weight += campaign.weight * wl.base_weight
                    finding.add_tag(f"campaign:{campaign.name}")
        return weight

    @staticmethod
    def _keyword_hit(
        term: str, is_regex: bool, case_sensitive: bool, text: str, haystack: str
    ) -> bool:
        """Evaluate a single keyword (literal or regex) against the text."""
        if is_regex:
            flags = 0 if case_sensitive else re.I
            return re.search(term, text, flags) is not None
        return (term if case_sensitive else term.lower()) in (
            text if case_sensitive else haystack
        )

    @staticmethod
    def _text(finding: Finding) -> str:
        """Concatenate the searchable surfaces of a finding."""
        normalized = finding.normalized_data.get("text", "")
        return f"{finding.title}\n{finding.description}\n{normalized}"
