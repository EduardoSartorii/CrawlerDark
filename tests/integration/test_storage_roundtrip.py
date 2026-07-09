"""Testes de round-trip do storage (domínio → SQL → domínio)."""

from __future__ import annotations

import pytest

from threat_hunting.core.domain.builders import FindingBuilder
from threat_hunting.core.domain.entities import Indicator, WatchlistItem, WatchlistKind
from threat_hunting.core.domain.value_objects import (
    Category,
    IndicatorType,
    Severity,
    SourceRef,
)


@pytest.mark.asyncio
async def test_finding_persist_and_read_back(uow_factory):
    src = SourceRef(source="s", connector="ut", url="https://ex.com/1", author="jane")
    f = (
        FindingBuilder()
        .title("dump")
        .description("john@x.com c2 evil.example")
        .source(src)
        .category(Category.LEAK)
        .severity(Severity.HIGH)
        .score(75.5)
        .tag("phishing", "urgent")
        .build()
    )
    f.add_indicator(Indicator(type=IndicatorType.DOMAIN, value="evil.example"))
    f.add_indicator(Indicator(type=IndicatorType.EMAIL, value="john@x.com"))

    async with uow_factory() as uow:
        await uow.findings.add(f)
        await uow.commit()

    async with uow_factory() as uow:
        loaded = await uow.findings.get(f.id)
    assert loaded is not None
    assert loaded.title == "dump"
    assert loaded.severity is Severity.HIGH
    assert loaded.category is Category.LEAK
    assert float(loaded.score) == 75.5
    assert {"phishing", "urgent"}.issubset(loaded.tags)
    assert len(loaded.indicators) == 2
    assert {i.type for i in loaded.indicators} == {IndicatorType.DOMAIN, IndicatorType.EMAIL}


@pytest.mark.asyncio
async def test_watchlist_bulk_replace(uow_factory):
    async with uow_factory() as uow:
        await uow.watchlists.bulk_replace(
            [
                WatchlistItem(kind=WatchlistKind.BRAND, value="AcmeCorp"),
                WatchlistItem(kind=WatchlistKind.THREAT_ACTOR, value="LockBit"),
            ]
        )
        await uow.commit()

    async with uow_factory() as uow:
        items = list(await uow.watchlists.all_enabled())
    assert len(items) == 2
    assert {i.value for i in items} == {"AcmeCorp", "LockBit"}


@pytest.mark.asyncio
async def test_find_unexported_filters_target(uow_factory):
    src = SourceRef(source="s", connector="ut")
    f = FindingBuilder().title("x").source(src).score(90).build()
    async with uow_factory() as uow:
        await uow.findings.add(f)
        await uow.commit()
    async with uow_factory() as uow:
        pending = list(await uow.findings.find_unexported("misp", min_score=50))
    assert len(pending) == 1
    # simulate export
    async with uow_factory() as uow:
        loaded = await uow.findings.get(f.id)
        assert loaded is not None
        loaded.mark_exported("misp")
        await uow.findings.update(loaded)
        await uow.commit()
    async with uow_factory() as uow:
        pending = list(await uow.findings.find_unexported("misp", min_score=50))
    assert len(pending) == 0
