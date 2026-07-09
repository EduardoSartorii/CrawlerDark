"""Testes do event bus e da serialização DTO."""

from __future__ import annotations

import pytest

from threat_hunting.core.application.dto import FindingDTO
from threat_hunting.core.application.events import InMemoryEventBus
from threat_hunting.core.domain.builders import FindingBuilder
from threat_hunting.core.domain.entities import Indicator
from threat_hunting.core.domain.events import DomainEvent, FindingCreated, ScoreComputed
from threat_hunting.core.domain.value_objects import IndicatorType, SourceRef


@pytest.mark.asyncio
async def test_event_bus_dispatches_to_typed_handlers():
    bus = InMemoryEventBus()
    seen: list[DomainEvent] = []

    async def h(e):  # type: ignore[no-untyped-def]
        seen.append(e)

    bus.subscribe(FindingCreated, h)
    bus.subscribe(ScoreComputed, h)
    from uuid import uuid4
    await bus.publish(FindingCreated(finding_id=uuid4(), connector="ut"))
    await bus.publish(ScoreComputed(finding_id=uuid4(), score=80.0))
    assert len(seen) == 2
    assert isinstance(seen[0], FindingCreated)
    assert isinstance(seen[1], ScoreComputed)


@pytest.mark.asyncio
async def test_event_bus_isolates_handler_errors():
    bus = InMemoryEventBus()

    async def broken(e):  # type: ignore[no-untyped-def]
        raise RuntimeError("boom")

    async def ok(e):  # type: ignore[no-untyped-def]
        ok.calls += 1  # type: ignore[attr-defined]

    ok.calls = 0  # type: ignore[attr-defined]
    bus.subscribe(FindingCreated, broken)
    bus.subscribe(FindingCreated, ok)
    from uuid import uuid4
    await bus.publish(FindingCreated(finding_id=uuid4(), connector="ut"))
    assert ok.calls == 1  # type: ignore[attr-defined]


def test_finding_dto_roundtrip():
    src = SourceRef(source="s", connector="ut", url="https://x.example")
    f = (
        FindingBuilder()
        .title("t")
        .description("d")
        .source(src)
        .score(50)
        .tag("phishing")
        .build()
    )
    f.add_indicator(Indicator(type=IndicatorType.IP, value="8.8.8.8"))
    dto = FindingDTO.from_entity(f)
    js = dto.model_dump_json()
    assert "phishing" in js
    assert "8.8.8.8" in js
    reloaded = FindingDTO.model_validate_json(js)
    assert reloaded.title == "t"
    assert reloaded.tags == ["phishing"]
    assert reloaded.url == "https://x.example"
