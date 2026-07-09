"""
Integration tests for the storage layer.

Tests cover SQLAlchemy repository with an in-memory SQLite database.
These verify the full persistence stack end-to-end.
"""

from __future__ import annotations

import pytest
import pytest_asyncio

from ...infrastructure.storage.database import DatabaseManager
from ...infrastructure.storage.sqlalchemy_repository import SQLAlchemyFindingRepository
from ...infrastructure.storage.unit_of_work import SQLAlchemyUnitOfWork
from ...core.domain.entities.finding import FindingStatus
from ...core.domain.repositories import PageSpec
from ..fixtures.factories import make_finding


@pytest.fixture
async def db():
    """Create an in-memory SQLite database for testing."""
    manager = DatabaseManager.sqlite(":memory:")
    await manager.create_tables()
    yield manager
    await manager.dispose()


@pytest.fixture
async def uow(db):
    """Create a Unit of Work backed by in-memory SQLite."""
    return SQLAlchemyUnitOfWork(db.session_factory)


@pytest.mark.asyncio
class TestSQLAlchemyFindingRepository:
    """Integration tests for SQLAlchemy Finding repository."""

    async def test_save_and_retrieve_finding(self, db):
        finding = make_finding(title="Integration Test Finding")
        async with db.session_factory() as session:
            repo = SQLAlchemyFindingRepository(session)
            saved = await repo.save(finding)
            await session.commit()
            retrieved = await repo.get_by_id(finding.id)

        assert retrieved is not None
        assert retrieved.title == "Integration Test Finding"
        assert retrieved.id == finding.id

    async def test_get_by_id_not_found_returns_none(self, db):
        async with db.session_factory() as session:
            repo = SQLAlchemyFindingRepository(session)
            result = await repo.get_by_id("nonexistent-id")
        assert result is None

    async def test_save_or_update_upserts(self, db):
        finding = make_finding()
        async with db.session_factory() as session:
            repo = SQLAlchemyFindingRepository(session)
            await repo.save(finding)
            await session.commit()

        finding.title = "Updated Title"
        async with db.session_factory() as session:
            repo = SQLAlchemyFindingRepository(session)
            await repo.save_or_update(finding)
            await session.commit()
            retrieved = await repo.get_by_id(finding.id)

        assert retrieved.title == "Updated Title"

    async def test_find_by_fingerprint(self, db):
        finding = make_finding()
        finding.fingerprint = "abc123fingerprint"
        async with db.session_factory() as session:
            repo = SQLAlchemyFindingRepository(session)
            await repo.save(finding)
            await session.commit()
            retrieved = await repo.get_by_fingerprint("abc123fingerprint")

        assert retrieved is not None
        assert retrieved.id == finding.id

    async def test_find_by_score_range(self, db):
        high_score = make_finding(score_value=8.5, title="High Score Finding")
        low_score = make_finding(score_value=2.0, title="Low Score Finding")
        async with db.session_factory() as session:
            repo = SQLAlchemyFindingRepository(session)
            await repo.save(high_score)
            await repo.save(low_score)
            await session.commit()
            page = await repo.find_by_score_range(min_score=7.0)

        ids = [f.id for f in page.items]
        assert high_score.id in ids
        assert low_score.id not in ids

    async def test_count_findings(self, db):
        async with db.session_factory() as session:
            repo = SQLAlchemyFindingRepository(session)
            for i in range(3):
                await repo.save(make_finding(title=f"Finding {i}"))
            await session.commit()
            count = await repo.count()

        assert count >= 3

    async def test_list_with_pagination(self, db):
        async with db.session_factory() as session:
            repo = SQLAlchemyFindingRepository(session)
            for i in range(10):
                await repo.save(make_finding(title=f"Finding {i}"))
            await session.commit()
            page = await repo.list(page=PageSpec(page=1, page_size=5))

        assert len(page.items) <= 5
        assert page.total >= 10


@pytest.mark.asyncio
class TestUnitOfWork:
    """Integration tests for the Unit of Work."""

    async def test_commit_persists_findings(self, db):
        finding = make_finding(title="UoW Test Finding")
        uow = SQLAlchemyUnitOfWork(db.session_factory)
        async with uow:
            await uow.findings.save(finding)

        # Verify persisted outside UoW
        async with db.session_factory() as session:
            repo = SQLAlchemyFindingRepository(session)
            retrieved = await repo.get_by_id(finding.id)
        assert retrieved is not None

    async def test_rollback_on_exception(self, db):
        finding = make_finding(title="Should Not Be Saved")
        uow = SQLAlchemyUnitOfWork(db.session_factory)

        try:
            async with uow:
                await uow.findings.save(finding)
                raise ValueError("Simulated error — should rollback")
        except ValueError:
            pass

        # Finding should not exist
        async with db.session_factory() as session:
            repo = SQLAlchemyFindingRepository(session)
            retrieved = await repo.get_by_id(finding.id)
        assert retrieved is None
