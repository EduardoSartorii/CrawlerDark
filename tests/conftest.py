"""Shared pytest fixtures and helpers.

Provides reusable builders (findings, watchlists, actors) and a fully-wired
in-memory :class:`Container` so tests exercise the real object graph without
touching disk or network.
"""

from __future__ import annotations

import pytest

from threat_hunting.config.container import Container
from threat_hunting.config.settings import (
    ExportSettings,
    OpsecSettings,
    Settings,
    StorageSettings,
)
from threat_hunting.core.domain.entities.finding import FindingBuilder
from threat_hunting.core.domain.entities.threat_actor import ThreatActor
from threat_hunting.core.domain.entities.watchlist import Keyword, KeywordType, Watchlist
from threat_hunting.core.domain.enums import Category, IndicatorType
from threat_hunting.core.domain.value_objects.indicator import Indicator


@pytest.fixture
def sample_indicator() -> Indicator:
    """A canonicalised domain indicator."""
    return Indicator(type=IndicatorType.DOMAIN, value="Evil[.]COM")


@pytest.fixture
def sample_finding():
    """Factory returning a fresh finding with an indicator and some text."""

    def _make(title: str = "leak", text: str = "creds admin@acme-corp.com 45.133.1.55"):
        return (
            FindingBuilder(title=title, connector="sample_paste", source="paste://sample")
            .description(text)
            .category(Category.DATA_LEAK)
            .add_indicator(Indicator(type=IndicatorType.EMAIL, value="admin@acme-corp.com"))
            .build()
        )

    return _make


@pytest.fixture
def watchlists() -> list[Watchlist]:
    """A watchlist exercising brand and generic keyword weights."""
    return [
        Watchlist(
            name="brands",
            keywords=[
                Keyword(term="ACME Corp", type=KeywordType.BRAND, weight=20.0),
                Keyword(term="fullz", type=KeywordType.GENERIC, weight=15.0),
            ],
        )
    ]


@pytest.fixture
def threat_actors() -> list[ThreatActor]:
    """A monitored threat actor with aliases."""
    return [ThreatActor(name="LockBit", aliases=["lockbit3", "lockbit affiliate"])]


@pytest.fixture
def container() -> Container:
    """A fully in-memory, offline container for integration tests."""
    settings = Settings(
        storage=StorageSettings(backend="memory"),
        export=ExportSettings(output_dir="/tmp/th-tests-exports"),
        opsec=OpsecSettings(offline=True),
        watchlists_file="config/watchlists.yml",
    )
    return Container(settings)
