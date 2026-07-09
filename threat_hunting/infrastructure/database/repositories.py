"""SQLAlchemy database models and repository implementations."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import Boolean, DateTime, Float, String, Text, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from threat_hunting.core.contracts.repositories import (
    IAuditRepository,
    IConnectorConfigRepository,
    ICorrelationRepository,
    IDetectionRuleRepository,
    IExportJobRepository,
    IFindingRepository,
    IScoreProfileRepository,
    IUnitOfWork,
    IWatchlistRepository,
)
from threat_hunting.core.domain.entities import (
    AuditLog,
    ConnectorConfig,
    CorrelationLink,
    DetectionRule,
    ExportJob,
    Finding,
    ScoreProfile,
    ScoreWeight,
    WatchlistEntry,
)


class Base(DeclarativeBase):
    """SQLAlchemy declarative base."""


class FindingModel(Base):
    """ORM model for Finding aggregate."""

    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    title: Mapped[str] = mapped_column(String(500))
    description: Mapped[str] = mapped_column(Text, default="")
    source: Mapped[str] = mapped_column(String(50))
    connector: Mapped[str] = mapped_column(String(100))
    category: Mapped[str] = mapped_column(String(50))
    severity: Mapped[str] = mapped_column(String(20))
    score: Mapped[float] = mapped_column(Float, default=0.0)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    data_json: Mapped[str] = mapped_column(Text)


class WatchlistModel(Base):
    __tablename__ = "watchlists"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    watchlist_type: Mapped[str] = mapped_column(String(50))
    value: Mapped[str] = mapped_column(String(500))
    label: Mapped[str] = mapped_column(String(200), default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    data_json: Mapped[str] = mapped_column(Text, default="{}")


class DetectionRuleModel(Base):
    __tablename__ = "detection_rules"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    rule_type: Mapped[str] = mapped_column(String(50))
    pattern: Mapped[str] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    data_json: Mapped[str] = mapped_column(Text, default="{}")


class ConnectorConfigModel(Base):
    __tablename__ = "connector_configs"

    name: Mapped[str] = mapped_column(String(100), primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    schedule_cron: Mapped[str] = mapped_column(String(100), default="")
    opsec_profile: Mapped[str] = mapped_column(String(100), default="default")
    data_json: Mapped[str] = mapped_column(Text, default="{}")


class AuditLogModel(Base):
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    action: Mapped[str] = mapped_column(String(100))
    actor: Mapped[str] = mapped_column(String(100), default="system")
    resource_type: Mapped[str] = mapped_column(String(100), default="")
    resource_id: Mapped[str] = mapped_column(String(200), default="")
    data_json: Mapped[str] = mapped_column(Text, default="{}")
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class CorrelationModel(Base):
    __tablename__ = "correlations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    source_id: Mapped[str] = mapped_column(String(36))
    target_id: Mapped[str] = mapped_column(String(200))
    correlation_type: Mapped[str] = mapped_column(String(50))
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    data_json: Mapped[str] = mapped_column(Text, default="{}")


def _finding_to_model(finding: Finding) -> FindingModel:
    return FindingModel(
        id=str(finding.id),
        title=finding.title,
        description=finding.description,
        source=finding.source.value,
        connector=finding.connector,
        category=finding.category.value,
        severity=finding.severity.value,
        score=finding.score,
        confidence=finding.confidence,
        created_at=finding.created_at,
        updated_at=finding.updated_at,
        data_json=finding.model_dump_json(),
    )


def _model_to_finding(model: FindingModel) -> Finding:
    return Finding.model_validate_json(model.data_json)


class SqlAlchemyFindingRepository(IFindingRepository):
    """SQLAlchemy implementation of IFindingRepository."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, finding: Finding) -> Finding:
        existing = await self._session.get(FindingModel, str(finding.id))
        if existing:
            for key, val in _finding_to_model(finding).__dict__.items():
                if not key.startswith("_"):
                    setattr(existing, key, val)
        else:
            self._session.add(_finding_to_model(finding))
        await self._session.flush()
        return finding

    async def get_by_id(self, finding_id: UUID) -> Finding | None:
        model = await self._session.get(FindingModel, str(finding_id))
        return _model_to_finding(model) if model else None

    async def list_all(self, limit: int = 100, offset: int = 0) -> list[Finding]:
        result = await self._session.execute(select(FindingModel).offset(offset).limit(limit))
        return [_model_to_finding(m) for m in result.scalars()]

    async def find_by_connector(self, connector: str, limit: int = 100) -> list[Finding]:
        result = await self._session.execute(
            select(FindingModel).where(FindingModel.connector == connector).limit(limit)
        )
        return [_model_to_finding(m) for m in result.scalars()]

    async def find_by_hash(self, content_hash: str) -> Finding | None:
        return None

    async def delete(self, finding_id: UUID) -> bool:
        model = await self._session.get(FindingModel, str(finding_id))
        if model:
            await self._session.delete(model)
            return True
        return False


class SqlAlchemyWatchlistRepository(IWatchlistRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, entry: WatchlistEntry) -> WatchlistEntry:
        model = WatchlistModel(
            id=str(entry.id), watchlist_type=entry.watchlist_type,
            value=entry.value, label=entry.label, enabled=entry.enabled,
            data_json=entry.model_dump_json(),
        )
        await self._session.merge(model)
        await self._session.flush()
        return entry

    async def list_enabled(self, watchlist_type: str | None = None) -> list[WatchlistEntry]:
        query = select(WatchlistModel).where(WatchlistModel.enabled.is_(True))
        if watchlist_type:
            query = query.where(WatchlistModel.watchlist_type == watchlist_type)
        result = await self._session.execute(query)
        return [WatchlistEntry.model_validate_json(m.data_json) for m in result.scalars()]

    async def delete(self, entry_id: UUID) -> bool:
        model = await self._session.get(WatchlistModel, str(entry_id))
        if model:
            await self._session.delete(model)
            return True
        return False


class SqlAlchemyDetectionRuleRepository(IDetectionRuleRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def list_enabled(self) -> list[DetectionRule]:
        result = await self._session.execute(
            select(DetectionRuleModel).where(DetectionRuleModel.enabled.is_(True))
        )
        rules = []
        for m in result.scalars():
            try:
                rules.append(DetectionRule.model_validate_json(m.data_json))
            except Exception:
                rules.append(DetectionRule(
                    id=UUID(m.id), name=m.name, rule_type=m.rule_type, pattern=m.pattern,
                ))
        return rules

    async def save(self, rule: DetectionRule) -> DetectionRule:
        model = DetectionRuleModel(
            id=str(rule.id), name=rule.name, rule_type=rule.rule_type,
            pattern=rule.pattern, enabled=rule.enabled, data_json=rule.model_dump_json(),
        )
        await self._session.merge(model)
        await self._session.flush()
        return rule


class InMemoryScoreProfileRepository(IScoreProfileRepository):
    """In-memory score profile for initial deployment."""

    def __init__(self) -> None:
        self._profile = ScoreProfile(
            name="default",
            weights=[ScoreWeight(dimension=k, weight=v) for k, v in {
                "regex_match": 10.0, "vip_match": 25.0, "ioc_match": 12.0,
                "credential": 20.0, "card": 25.0, "source_reputation": 10.0,
            }.items()],
            threshold_auto_export=70.0,
        )

    async def get_default(self) -> ScoreProfile:
        return self._profile

    async def save(self, profile: ScoreProfile) -> ScoreProfile:
        self._profile = profile
        return profile


class SqlAlchemyConnectorConfigRepository(IConnectorConfigRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get(self, name: str) -> ConnectorConfig | None:
        model = await self._session.get(ConnectorConfigModel, name)
        if not model:
            return ConnectorConfig(name=name, enabled=True)
        return ConnectorConfig(
            name=model.name, enabled=model.enabled,
            schedule_cron=model.schedule_cron, opsec_profile=model.opsec_profile,
            metadata=json.loads(model.data_json) if model.data_json else {},
        )

    async def list_all(self) -> list[ConnectorConfig]:
        result = await self._session.execute(select(ConnectorConfigModel))
        return [
            ConnectorConfig(name=m.name, enabled=m.enabled, schedule_cron=m.schedule_cron)
            for m in result.scalars()
        ]

    async def save(self, config: ConnectorConfig) -> ConnectorConfig:
        model = ConnectorConfigModel(
            name=config.name, enabled=config.enabled,
            schedule_cron=config.schedule_cron, opsec_profile=config.opsec_profile,
            data_json=json.dumps(config.metadata),
        )
        await self._session.merge(model)
        await self._session.flush()
        return config

    async def set_enabled(self, name: str, enabled: bool) -> ConnectorConfig:
        config = await self.get(name) or ConnectorConfig(name=name)
        config.enabled = enabled
        return await self.save(config)


class SqlAlchemyCorrelationRepository(ICorrelationRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, link: CorrelationLink) -> CorrelationLink:
        model = CorrelationModel(
            id=str(link.id), source_id=str(link.source_id),
            target_id=link.target_id, correlation_type=link.correlation_type,
            confidence=link.confidence, data_json=link.model_dump_json(),
        )
        self._session.add(model)
        await self._session.flush()
        return link

    async def find_by_source(self, source_id: UUID) -> list[CorrelationLink]:
        result = await self._session.execute(
            select(CorrelationModel).where(CorrelationModel.source_id == str(source_id))
        )
        return [CorrelationLink.model_validate_json(m.data_json) for m in result.scalars()]

    async def find_by_target(self, target_id: str) -> list[CorrelationLink]:
        result = await self._session.execute(
            select(CorrelationModel).where(CorrelationModel.target_id == target_id)
        )
        return [CorrelationLink.model_validate_json(m.data_json) for m in result.scalars()]


class SqlAlchemyAuditRepository(IAuditRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def append(self, log: AuditLog) -> AuditLog:
        model = AuditLogModel(
            id=str(log.id), action=log.action, actor=log.actor,
            resource_type=log.resource_type, resource_id=log.resource_id,
            data_json=json.dumps(log.details), timestamp=log.timestamp,
        )
        self._session.add(model)
        await self._session.flush()
        return log

    async def list_recent(self, limit: int = 100) -> list[AuditLog]:
        result = await self._session.execute(
            select(AuditLogModel).order_by(AuditLogModel.timestamp.desc()).limit(limit)
        )
        return [
            AuditLog(
                id=UUID(m.id), action=m.action, actor=m.actor,
                resource_type=m.resource_type, resource_id=m.resource_id,
                details=json.loads(m.data_json), timestamp=m.timestamp,
            )
            for m in result.scalars()
        ]


class SqlAlchemyUnitOfWork(IUnitOfWork):
    """Unit of Work for atomic database transactions."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory
        self._session: AsyncSession | None = None

    async def __aenter__(self) -> SqlAlchemyUnitOfWork:
        self._session = self._session_factory()
        self.findings = SqlAlchemyFindingRepository(self._session)
        self.watchlists = SqlAlchemyWatchlistRepository(self._session)
        self.rules = SqlAlchemyDetectionRuleRepository(self._session)
        self.correlations = SqlAlchemyCorrelationRepository(self._session)
        self.audit = SqlAlchemyAuditRepository(self._session)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        if exc_type:
            await self.rollback()
        else:
            await self.commit()
        if self._session:
            await self._session.close()

    async def commit(self) -> None:
        if self._session:
            await self._session.commit()

    async def rollback(self) -> None:
        if self._session:
            await self._session.rollback()


async def init_database(database_url: str) -> tuple[Any, async_sessionmaker[AsyncSession]]:
    """Initialize database engine and create tables."""
    engine = create_async_engine(database_url, echo=False)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    return engine, session_factory
