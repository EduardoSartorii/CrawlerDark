"""Unit tests for detection and scoring engines."""

from __future__ import annotations

from datetime import UTC, datetime

from threat_hunting.core.contracts import StageContext
from threat_hunting.detections.engine import DynamicDetectionEngine
from threat_hunting.domain.entities import DetectionRule, RuleType, ScoringPolicy, WatchlistProfile
from threat_hunting.scoring.engine import WeightedScoringEngine
from threat_hunting.scoring.strategies import SignalPresenceStrategy, ThreatActorMatchStrategy, VipMatchStrategy


def test_detection_engine_matches_regex_and_ioc() -> None:
    rules = [
        DetectionRule(id="r1", name="regex", type=RuleType.regex, pattern="credential"),
        DetectionRule(id="r2", name="ioc", type=RuleType.ioc_match),
    ]
    watchlist = WatchlistProfile(ioc_lists=["198.51.100.10"])
    engine = DynamicDetectionEngine(rules=rules, watchlist=watchlist)
    context = StageContext(
        connector_name="reddit",
        run_id="run-1",
        started_at=datetime.now(UTC),
        metadata={},
    )
    output = engine.run(
        [
            {
                "title": "Credential leaked",
                "description": "Paste with IOC",
                "normalized_data": {},
                "indicators": [{"type": "ip", "value": "198.51.100.10"}],
                "tags": [],
            }
        ],
        context,
    )
    assert "r1" in output[0]["matched_rules"]
    assert "r2" in output[0]["matched_rules"]


def test_weighted_scoring_engine_applies_strategies() -> None:
    policy = ScoringPolicy(
        threshold_misp_auto_export=80,
        weights={"regex_match": 20, "vip_match": 30, "threat_actor_match": 40},
    )
    watchlist = WatchlistProfile(vips=["ceo@example.com"], threat_actors=["blackfox"])
    engine = WeightedScoringEngine(
        policy=policy,
        watchlist=watchlist,
        strategies=[
            SignalPresenceStrategy("regex_match"),
            VipMatchStrategy(),
            ThreatActorMatchStrategy(),
        ],
    )
    context = StageContext(
        connector_name="github",
        run_id="run-2",
        started_at=datetime.now(UTC),
        metadata={},
    )
    output = engine.run(
        [
            {
                "title": "Credential dump for ceo@example.com",
                "description": "Mentioning actor",
                "signals": ["regex_match"],
                "normalized_data": {"threat_actor": "blackfox"},
            }
        ],
        context,
    )
    assert output[0]["score"] == 90
    assert output[0]["severity"] == "critical"
