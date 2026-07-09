"""Unit tests for database repositories."""

import pytest
import pytest_asyncio

from threat_hunting.core.domain.entities import (
    AuditLog,
    ConnectorConfig,
    CorrelationLink,
    DetectionRule,
    Finding,
    WatchlistEntry,
)
from threat_hunting.core.domain.enums import SourceType
from threat_hunting.infrastructure.database.repositories import (
    SqlAlchemyAuditRepository,
    SqlAlchemyConnectorConfigRepository,
    SqlAlchemyCorrelationRepository,
    SqlAlchemyDetectionRuleRepository,
    SqlAlchemyFindingRepository,
    SqlAlchemyUnitOfWork,
    SqlAlchemyWatchlistRepository,
    init_database,
)


@pytest_asyncio.fixture
async def session_factory(tmp_path):
    url = f"sqlite+aiosqlite:///{tmp_path}/repo_test.db"
    _, factory = await init_database(url)
    return factory


@pytest.mark.asyncio
async def test_finding_repository(session_factory):
    async with session_factory() as session:
        repo = SqlAlchemyFindingRepository(session)
        finding = Finding(title="Repo Test", source=SourceType.API, connector="test")
        saved = await repo.save(finding)
        await session.commit()

        retrieved = await repo.get_by_id(saved.id)
        assert retrieved is not None
        assert retrieved.title == "Repo Test"

        all_findings = await repo.list_all()
        assert len(all_findings) == 1

        by_connector = await repo.find_by_connector("test")
        assert len(by_connector) == 1

        deleted = await repo.delete(saved.id)
        assert deleted is True
        await session.commit()


@pytest.mark.asyncio
async def test_watchlist_repository(session_factory):
    async with session_factory() as session:
        repo = SqlAlchemyWatchlistRepository(session)
        entry = WatchlistEntry(watchlist_type="keyword", value="test")
        await repo.save(entry)
        await session.commit()

        entries = await repo.list_enabled("keyword")
        assert len(entries) == 1

        await repo.delete(entry.id)
        await session.commit()


@pytest.mark.asyncio
async def test_detection_rule_repository(session_factory):
    async with session_factory() as session:
        repo = SqlAlchemyDetectionRuleRepository(session)
        rule = DetectionRule(name="test_rule", rule_type="keyword", pattern="malware")
        await repo.save(rule)
        await session.commit()

        rules = await repo.list_enabled()
        assert len(rules) == 1


@pytest.mark.asyncio
async def test_connector_config_repository(session_factory):
    async with session_factory() as session:
        repo = SqlAlchemyConnectorConfigRepository(session)
        config = ConnectorConfig(name="reddit", enabled=True)
        await repo.save(config)
        await session.commit()

        retrieved = await repo.get("reddit")
        assert retrieved is not None
        assert retrieved.enabled is True

        updated = await repo.set_enabled("reddit", False)
        assert updated.enabled is False

        all_configs = await repo.list_all()
        assert len(all_configs) >= 1


@pytest.mark.asyncio
async def test_correlation_repository(session_factory):
    async with session_factory() as session:
        repo = SqlAlchemyCorrelationRepository(session)
        finding = Finding(title="F", source=SourceType.API, connector="test")
        link = CorrelationLink(source_id=finding.id, target_id="target-1", correlation_type="ip")
        await repo.save(link)
        await session.commit()

        by_source = await repo.find_by_source(finding.id)
        assert len(by_source) == 1

        by_target = await repo.find_by_target("target-1")
        assert len(by_target) == 1


@pytest.mark.asyncio
async def test_audit_repository(session_factory):
    async with session_factory() as session:
        repo = SqlAlchemyAuditRepository(session)
        log = AuditLog(action="test.action", resource_id="r1")
        await repo.append(log)
        await session.commit()

        recent = await repo.list_recent()
        assert len(recent) == 1


@pytest.mark.asyncio
async def test_unit_of_work(session_factory):
    async with SqlAlchemyUnitOfWork(session_factory) as uow:
        finding = Finding(title="UoW", source=SourceType.API, connector="test")
        await uow.findings.save(finding)
    async with session_factory() as session:
        repo = SqlAlchemyFindingRepository(session)
        results = await repo.list_all()
        assert len(results) == 1
