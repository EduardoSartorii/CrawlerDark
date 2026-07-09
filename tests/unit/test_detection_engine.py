"""Testes dos detectores (regex, keyword, ioc list)."""

from __future__ import annotations

from pathlib import Path

from threat_hunting.core.domain.builders import FindingBuilder
from threat_hunting.core.domain.entities import Indicator, WatchlistItem, WatchlistKind
from threat_hunting.core.domain.value_objects import IndicatorType, Severity, SourceRef
from threat_hunting.infrastructure.detections import (
    CompositeDetectionEngine,
    IOCListDetector,
    KeywordDetector,
    RegexDetector,
    SigmaKeywordDetector,
)


def _finding(text: str):
    return (
        FindingBuilder()
        .title(text[:60])
        .description(text)
        .source(SourceRef(source="t", connector="ut"))
        .build()
    )


REGEX_RULES = [
    {
        "id": "regex.email",
        "pattern": r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
        "category": "IOC",
        "severity": "LOW",
        "confidence": 60,
        "tags": ["email"],
    },
    {
        "id": "regex.aws",
        "pattern": r"AKIA[0-9A-Z]{16}",
        "category": "CREDENTIAL",
        "severity": "CRITICAL",
        "confidence": 95,
        "tags": ["aws"],
    },
]


class TestRegexDetector:
    async def test_matches_and_escalates_severity(self):
        f = _finding("email me at admin@corp.example, key AKIAIOSFODNN7EXAMPLE")
        f = await RegexDetector(REGEX_RULES).detect(f)
        assert f.severity is Severity.CRITICAL
        rule_events = [e for e in f.timeline if e.kind == "rule.matched"]
        assert any(e.payload["rule_id"] == "regex.aws" for e in rule_events)
        assert any(e.payload["rule_id"] == "regex.email" for e in rule_events)


class TestKeywordDetector:
    async def test_matches_watchlist_item_case_insensitive(self):
        f = _finding("Rumor of AcmeCorp data breach and LockBit involvement")
        watchlist = [
            WatchlistItem(kind=WatchlistKind.BRAND, value="AcmeCorp"),
            WatchlistItem(kind=WatchlistKind.THREAT_ACTOR, value="LockBit"),
        ]
        f = await KeywordDetector(watchlist).detect(f)
        assert "watch:brand" in f.tags
        assert "watch:threat_actor" in f.tags
        assert f.severity >= Severity.HIGH


class TestIOCListDetector:
    async def test_indicator_in_list(self, tmp_path: Path):
        listfile = tmp_path / "iocs.txt"
        listfile.write_text("evil.example\n185.220.101.1\n", encoding="utf-8")
        f = _finding("dummy")
        f.add_indicator(Indicator(type=IndicatorType.DOMAIN, value="evil.example"))
        f = await IOCListDetector([str(listfile)]).detect(f)
        assert "rule:ioc" in f.tags


class TestSigmaKeywordDetector:
    async def test_loads_rule_and_matches(self, tmp_path: Path):
        rule = tmp_path / "combolist.yml"
        rule.write_text(
            "title: combo\nid: r1\ndetection:\n  keywords: [combolist]\n  condition: keywords\nlevel: high\n",
            encoding="utf-8",
        )
        f = _finding("dump: combolist inside")
        f = await SigmaKeywordDetector(str(tmp_path)).detect(f)
        assert "rule:sigma" in f.tags


class TestCompositeDetectionEngine:
    async def test_runs_detectors_in_order(self):
        f = _finding("admin@corp.example key AKIAIOSFODNN7EXAMPLE plus LockBit rumor")
        engine = CompositeDetectionEngine(
            [
                RegexDetector(REGEX_RULES),
                KeywordDetector([WatchlistItem(kind=WatchlistKind.THREAT_ACTOR, value="LockBit")]),
            ]
        )
        f = await engine.detect(f)
        assert f.severity is Severity.CRITICAL  # AWS regex bumps to CRITICAL
        assert "watch:threat_actor" in f.tags
