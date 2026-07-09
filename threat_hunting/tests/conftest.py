"""Pytest fixtures for platform testing."""

from __future__ import annotations

import pytest
import pytest_asyncio

from threat_hunting.core.domain.entities import DetectionRule, Finding, ScoreProfile, ScoreWeight, WatchlistEntry
from threat_hunting.core.domain.enums import FindingCategory, Severity, SourceType
from threat_hunting.infrastructure.deduplication.engine import DeduplicationEngine
from threat_hunting.infrastructure.detections.engine import DetectionEngine
from threat_hunting.infrastructure.scoring.engine import ScoringEngine


class InMemoryFindingRepo:
  async def save(self, finding):
    return finding
  async def get_by_id(self, fid):
    return None
  async def list_all(self, limit=100, offset=0):
    return []
  async def find_by_connector(self, connector, limit=100):
    return []
  async def find_by_hash(self, h):
    return None
  async def delete(self, fid):
    return False


class InMemoryWatchlistRepo:
    def __init__(self):
        self._entries = []

    async def save(self, entry):
        self._entries.append(entry)
        return entry

    async def list_enabled(self, watchlist_type=None):
        entries = [e for e in self._entries if e.enabled]
        if watchlist_type:
            entries = [e for e in entries if e.watchlist_type == watchlist_type]
        return entries

    async def delete(self, eid):
        return False


class InMemoryRuleRepo:
    def __init__(self, rules=None):
        self._rules = rules or []

    async def list_enabled(self):
        return [r for r in self._rules if r.enabled]

    async def save(self, rule):
        self._rules.append(rule)
        return rule


class InMemoryScoreRepo:
    def __init__(self):
        self._profile = ScoreProfile(
            name="test",
            weights=[ScoreWeight(dimension="ioc_match", weight=10.0)],
            threshold_auto_export=70.0,
        )

    async def get_default(self):
        return self._profile

    async def save(self, profile):
        self._profile = profile
        return profile


@pytest.fixture
def sample_finding():
    return Finding(
        title="Test credential leak",
        description="password leak detected in dark web forum",
        source=SourceType.DARKWEB,
        connector="darkweb",
        category=FindingCategory.CREDENTIAL_LEAK,
        severity=Severity.MEDIUM,
    )


@pytest.fixture
def detection_engine():
    rules = [
        DetectionRule(name="leak_kw", rule_type="keyword", pattern="password leak", severity=Severity.HIGH),
        DetectionRule(name="ransom", rule_type="keyword", pattern="ransomware", severity=Severity.HIGH),
    ]
    return DetectionEngine(InMemoryRuleRepo(rules), InMemoryWatchlistRepo())


@pytest.fixture
def scoring_engine():
    return ScoringEngine(InMemoryScoreRepo())


@pytest.fixture
def dedup_engine():
    return DeduplicationEngine()
