"""
Test Configuration and Shared Fixtures
========================================

Provides pytest fixtures for:
    - In-memory SQLite database (async)
    - Unit of Work with test session
    - Pre-populated domain objects (Findings, Indicators, Keywords, VIPs)
    - Mock event bus
    - Mock connectors
    - OPSEC layer (no real proxies, no rate limiting)
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import AsyncIterator
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio

from threat_hunting.core.domain.entities.finding import Finding, FindingStatus
from threat_hunting.core.domain.entities.indicator import Indicator
from threat_hunting.core.domain.entities.keyword import Keyword, KeywordType
from threat_hunting.core.domain.entities.rule import Rule, RuleType
from threat_hunting.core.domain.entities.vip import VIP, VIPType
from threat_hunting.core.domain.entities.threat_actor import ThreatActor
from threat_hunting.core.domain.value_objects.category import Category
from threat_hunting.core.domain.value_objects.indicator_type import IndicatorType
from threat_hunting.core.domain.value_objects.score import Score
from threat_hunting.core.domain.value_objects.severity import Severity
from threat_hunting.core.domain.value_objects.source import SourceType
from threat_hunting.infrastructure.database.session import DatabaseSession
from threat_hunting.infrastructure.event_bus.in_memory_bus import InMemoryEventBus
from threat_hunting.infrastructure.opsec.layer import OpsecLayer, OpsecProfile
from threat_hunting.infrastructure.storage.unit_of_work import SQLAlchemyUnitOfWork


# ── Database fixtures ──────────────────────────────────────────────────────────

@pytest.fixture(scope="function")
def event_loop():
    """Provide a fresh event loop for each test."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="function")
async def db_session() -> AsyncIterator[DatabaseSession]:
    """Provide an in-memory SQLite session for testing."""
    db = DatabaseSession("sqlite+aiosqlite:///:memory:", echo=False)
    await db.create_all()
    yield db
    await db.drop_all()
    await db.close()


@pytest_asyncio.fixture(scope="function")
async def uow(db_session: DatabaseSession) -> SQLAlchemyUnitOfWork:
    """Provide a Unit of Work backed by the test database."""
    return SQLAlchemyUnitOfWork(db_session)


# ── Infrastructure fixtures ────────────────────────────────────────────────────

@pytest.fixture
def event_bus() -> InMemoryEventBus:
    """Provide an in-memory event bus."""
    return InMemoryEventBus()


@pytest.fixture
def opsec_layer() -> OpsecLayer:
    """Provide an OPSEC layer with a no-proxy test profile."""
    profile = OpsecProfile(
        name="test",
        proxy=None,
        user_agent="TestBot/1.0",
        timeout=5,
        max_retries=1,
        backoff_factor=0.1,
        verify_ssl=False,
        rate_limit_rps=100.0,  # No throttling in tests
    )
    return OpsecLayer(profiles={"standard": profile, "darkweb": profile, "test": profile})


# ── Domain object fixtures ──────────────────────────────────────────────────────

@pytest.fixture
def sample_finding() -> Finding:
    """A fully populated Finding for use in tests."""
    return Finding(
        title="Test Finding: Credential Leak Detected",
        description="email:password credentials found in a public paste.",
        source=SourceType.PASTE,
        connector="paste",
        category=Category.CREDENTIAL_LEAK,
        status=FindingStatus.NORMALIZED,
        source_url="https://pastebin.com/abc123",
        source_id="abc123",
        tags=["paste", "credentials"],
        normalized_data={"platform": "pastebin", "credential_count": 150},
        raw_data="test@example.com:password123\nuser@company.com:secret456",
    )


@pytest.fixture
def scored_finding(sample_finding: Finding) -> Finding:
    """A Finding with a score assigned."""
    sample_finding.set_score(Score.from_raw(7.5, confidence=0.9))
    return sample_finding


@pytest.fixture
def sample_indicator() -> Indicator:
    """A sample IP Indicator."""
    return Indicator(
        type=IndicatorType.IP,
        value="192.168.100.1",
        context="test connector",
        sources=["test"],
        tags=["ip", "test"],
    )


@pytest.fixture
def sample_keyword() -> Keyword:
    """A sample credential-hunting keyword."""
    return Keyword(
        value="credential leak",
        type=KeywordType.PLAIN,
        is_enabled=True,
        description="Match credential leak mentions",
    )


@pytest.fixture
def sample_vip() -> VIP:
    """A sample VIP monitoring entity."""
    return VIP(
        name="John CEO",
        type=VIPType.PERSON,
        organization="ACME Corp",
        role="CEO",
        emails=["john.ceo@acme.com"],
        aliases=["John Smith"],
        domains=["acme.com"],
        is_enabled=True,
    )


@pytest.fixture
def sample_threat_actor() -> ThreatActor:
    """A sample threat actor entity."""
    return ThreatActor(
        name="LazarusGroup",
        aliases=["Hidden Cobra", "APT38"],
        description="North Korean state-sponsored threat actor",
        country="KP",
        motivation=["financial", "espionage"],
    )


@pytest.fixture
def sample_rule() -> Rule:
    """A sample regex detection rule."""
    return Rule(
        name="CPF Detection",
        type=RuleType.REGEX,
        pattern=r"\d{3}\.\d{3}\.\d{3}-\d{2}",
        description="Detect Brazilian CPF numbers",
        confidence=0.9,
        is_enabled=True,
    )
