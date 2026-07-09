"""Unit tests for deduplication engine."""

import pytest

from threat_hunting.core.domain.entities import Finding
from threat_hunting.core.domain.enums import SourceType


@pytest.mark.asyncio
async def test_dedup_identical(dedup_engine):
    f1 = Finding(title="Same", description="content", source=SourceType.API, connector="test")
    f2 = Finding(title="Same", description="content", source=SourceType.API, connector="test")
    result = await dedup_engine.deduplicate([f1, f2])
    assert len(result) == 1


@pytest.mark.asyncio
async def test_dedup_different(dedup_engine):
    f1 = Finding(title="A", description="aaa", source=SourceType.API, connector="test")
    f2 = Finding(title="B", description="bbb", source=SourceType.API, connector="test")
    result = await dedup_engine.deduplicate([f1, f2])
    assert len(result) == 2
