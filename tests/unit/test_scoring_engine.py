"""Testes do WeightedScoringEngine."""

from __future__ import annotations

from threat_hunting.core.domain.builders import FindingBuilder
from threat_hunting.core.domain.entities import Indicator
from threat_hunting.core.domain.value_objects import (
    Category,
    IndicatorType,
    Severity,
    SourceRef,
)
from threat_hunting.infrastructure.config.schemas import ScoringConfig
from threat_hunting.infrastructure.scoring import WeightedScoringEngine


def _config() -> ScoringConfig:
    return ScoringConfig(
        base_score=10,
        weights={
            "regex_match": 5,
            "yara_match": 20,
            "sigma_match": 15,
            "vip_match": 30,
            "ioc_match": 10,
            "credential": 25,
            "card": 25,
            "email": 8,
            "document": 15,
            "cpf": 20,
            "cnpj": 15,
            "domain_watch": 15,
            "threat_actor": 30,
            "brand": 15,
            "indicator_count_step": 2,
        },
        severity_multiplier={"INFO": 0.5, "LOW": 0.8, "MEDIUM": 1.0, "HIGH": 1.2, "CRITICAL": 1.5},
        source_bonus={"darkweb": 15, "rss": 2, "api": 3},
        cap={"min": 0, "max": 100},
    )


def _finding(**kw):
    src = SourceRef(source=kw.pop("source", "unit"), connector=kw.pop("connector", "ut"))
    return (
        FindingBuilder()
        .title(kw.pop("title", "t"))
        .description(kw.pop("description", ""))
        .source(src)
        .category(kw.pop("category", Category.OTHER))
        .severity(kw.pop("severity", Severity.MEDIUM))
        .build()
    )


class TestWeightedScoringEngine:
    async def test_baseline_finding(self):
        f = _finding()
        engine = WeightedScoringEngine(_config())
        score = await engine.score(f)
        assert 0 <= score.value <= 100
        assert score.value >= 10  # base

    async def test_credential_indicator_bumps_score(self):
        f = _finding()
        f.add_indicator(Indicator(type=IndicatorType.CREDENTIAL, value="userpass:x"))
        engine = WeightedScoringEngine(_config())
        assert (await engine.score(f)).value > 30

    async def test_darkweb_source_bonus_applied(self):
        f = _finding(source="darkweb", connector="darkweb_generic")
        f.add_indicator(Indicator(type=IndicatorType.EMAIL, value="a@b.com"))
        engine = WeightedScoringEngine(_config())
        assert (await engine.score(f)).value >= 20

    async def test_score_capped_at_100(self):
        f = _finding(severity=Severity.CRITICAL, source="darkweb", connector="darkweb_generic")
        for i in range(10):
            f.add_indicator(Indicator(type=IndicatorType.EMAIL, value=f"u{i}@b.com"))
        f.add_indicator(Indicator(type=IndicatorType.CREDENTIAL, value="aws_access_key:AKIA..."))
        f.add_indicator(Indicator(type=IndicatorType.CARD_PAN, value="411111******1111"))
        f.record_event("rule.matched", "r", {"engine": "yara", "rule_id": "y"})
        f.record_event("rule.matched", "r", {"engine": "regex", "rule_id": "r"})
        f.add_tags("watch:threat_actor", "watch:vip", "watch:brand")
        engine = WeightedScoringEngine(_config())
        assert (await engine.score(f)).value == 100.0
