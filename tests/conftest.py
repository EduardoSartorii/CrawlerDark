"""Fixtures compartilhadas entre os testes."""

from __future__ import annotations

import pytest
import pytest_asyncio

from threat_hunting.core.domain.builders import FindingBuilder
from threat_hunting.core.domain.value_objects import Category, Severity, SourceRef
from threat_hunting.infrastructure.config.schemas import (
    JSONStorage,
    SQLAlchemyStorage,
    StorageConfig,
)
from threat_hunting.infrastructure.storage import StorageFactory


@pytest.fixture
def source_ref() -> SourceRef:
    return SourceRef(source="unit-test", connector="ut", url="https://example.com/x")


@pytest.fixture
def sample_finding(source_ref):  # type: ignore[no-untyped-def]
    return (
        FindingBuilder()
        .title("sample leak dump")
        .description("john@example.com password:hunter2 4111 1111 1111 1111")
        .source(source_ref)
        .category(Category.CREDENTIAL)
        .severity(Severity.MEDIUM)
        .build()
    )


@pytest_asyncio.fixture
async def in_memory_storage():
    cfg = StorageConfig(
        backend="sqlalchemy",
        sqlalchemy=SQLAlchemyStorage(
            url="sqlite+aiosqlite:///:memory:", echo=False, pool_size=5, max_overflow=10
        ),
        json_storage=JSONStorage(root="./data/findings"),
    )
    factory = StorageFactory(cfg)
    await factory.create_schema()
    try:
        yield factory
    finally:
        await factory.dispose()


@pytest_asyncio.fixture
async def uow_factory(in_memory_storage):  # type: ignore[no-untyped-def]
    return in_memory_storage.uow_factory()
