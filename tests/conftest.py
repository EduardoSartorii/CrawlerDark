"""Shared pytest fixtures and lightweight test doubles.

These fixtures build real domain objects and in-memory adapters so tests
exercise genuine behaviour without external services.
"""

from __future__ import annotations

import pytest

from threat_hunting.core.domain.entities import Finding, Indicator
from threat_hunting.core.domain.enums import Category, IndicatorType
from threat_hunting.infrastructure.config.settings import PlatformSettings
from threat_hunting.infrastructure.storage.memory_repo import InMemoryUnitOfWork


@pytest.fixture()
def settings() -> PlatformSettings:
    """A default, fully-populated settings object (no YAML/env needed)."""
    return PlatformSettings()


@pytest.fixture()
def memory_uow() -> InMemoryUnitOfWork:
    """A fresh in-memory Unit of Work."""
    return InMemoryUnitOfWork()


@pytest.fixture()
def leak_finding() -> Finding:
    """A representative high-signal finding used across tests."""
    finding = Finding(
        title="Alleged ACME Corp leak",
        description="database dump with john.doe@acme-corp.com:Password123",
        source="sample:demo",
        connector="sample",
        category=Category.LEAK_HUNTING,
        normalized_data={"text": "database dump acme-corp leak lockbit3"},
    )
    finding.add_indicator(Indicator(type=IndicatorType.EMAIL, value="john.doe@acme-corp.com"))
    finding.add_indicator(Indicator(type=IndicatorType.IPV4, value="185.220.101.45"))
    finding.add_indicator(Indicator(type=IndicatorType.CREDENTIAL, value="john.doe@acme-corp.com:Password123"))
    return finding
