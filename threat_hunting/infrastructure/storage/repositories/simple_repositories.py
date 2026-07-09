"""
Simple Repository Implementations
===================================

SQLAlchemy implementations for Indicator, Keyword, VIP, ThreatActor,
Rule, and ConnectorConfig repositories.

Pattern: ORM model ↔ domain entity conversion via _to_entity / _to_model helpers.
All methods are async and session-bound (session comes from UoW).
"""

from __future__ import annotations

import json
from datetime import datetime

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from threat_hunting.core.domain.entities.connector_config import ConnectorConfig
from threat_hunting.core.domain.entities.indicator import Indicator, EnrichmentData
from threat_hunting.core.domain.entities.keyword import Keyword, KeywordType
from threat_hunting.core.domain.entities.rule import Rule, RuleType, CompositeOperator
from threat_hunting.core.domain.entities.threat_actor import ThreatActor
from threat_hunting.core.domain.entities.vip import VIP, VIPType
from threat_hunting.core.domain.ports.repositories import (
    IConnectorConfigRepository,
    IIndicatorRepository,
    IKeywordRepository,
    IRuleRepository,
    IThreatActorRepository,
    IVIPRepository,
)
from threat_hunting.core.domain.value_objects.indicator_type import IndicatorType
from threat_hunting.core.domain.value_objects.source import SourceType
from threat_hunting.infrastructure.database.models import (
    ConnectorConfigModel,
    IndicatorModel,
    KeywordModel,
    RuleModel,
    ThreatActorModel,
    VIPModel,
)


class SQLAlchemyIndicatorRepository(IIndicatorRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, indicator: Indicator) -> None:
        existing = await self._session.get(IndicatorModel, indicator.id)
        model_data = {
            "id": indicator.id,
            "type": indicator.type.value,
            "value": indicator.value,
            "context": indicator.context,
            "confidence": indicator.confidence,
            "tags_json": json.dumps(indicator.tags),
            "sources_json": json.dumps(indicator.sources),
            "finding_ids_json": json.dumps(indicator.finding_ids),
            "enrichment_json": json.dumps(indicator.enrichment.model_dump(exclude_none=True)),
            "first_seen": indicator.first_seen,
            "last_seen": indicator.last_seen,
            "is_whitelisted": indicator.is_whitelisted,
            "is_blacklisted": indicator.is_blacklisted,
            "metadata_json": json.dumps(indicator.metadata),
        }
        if existing:
            for k, v in model_data.items():
                setattr(existing, k, v)
        else:
            self._session.add(IndicatorModel(**model_data))

    async def get_by_id(self, indicator_id: str) -> Indicator | None:
        m = await self._session.get(IndicatorModel, indicator_id)
        return self._to_entity(m) if m else None

    async def get_by_value(self, ioc_type: str, value: str) -> Indicator | None:
        q = select(IndicatorModel).where(
            and_(IndicatorModel.type == ioc_type, IndicatorModel.value == value)
        )
        r = await self._session.execute(q)
        m = r.scalar_one_or_none()
        return self._to_entity(m) if m else None

    async def list(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        ioc_type: str | None = None,
        since: datetime | None = None,
    ) -> list[Indicator]:
        q = select(IndicatorModel)
        if ioc_type:
            q = q.where(IndicatorModel.type == ioc_type)
        if since:
            q = q.where(IndicatorModel.first_seen >= since)
        q = q.limit(limit).offset(offset)
        r = await self._session.execute(q)
        return [self._to_entity(m) for m in r.scalars().all()]

    async def count(self) -> int:
        from sqlalchemy import func
        r = await self._session.execute(select(func.count()).select_from(IndicatorModel))
        return r.scalar_one()

    def _to_entity(self, m: IndicatorModel) -> Indicator:
        return Indicator(
            id=m.id,
            type=IndicatorType(m.type),
            value=m.value,
            context=m.context,
            confidence=m.confidence,
            tags=json.loads(m.tags_json or "[]"),
            sources=json.loads(m.sources_json or "[]"),
            finding_ids=json.loads(m.finding_ids_json or "[]"),
            enrichment=EnrichmentData(**json.loads(m.enrichment_json or "{}")),
            first_seen=m.first_seen,
            last_seen=m.last_seen,
            is_whitelisted=m.is_whitelisted,
            is_blacklisted=m.is_blacklisted,
            metadata=json.loads(m.metadata_json or "{}"),
        )


class SQLAlchemyKeywordRepository(IKeywordRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, keyword: Keyword) -> None:
        existing = await self._session.get(KeywordModel, keyword.id)
        data = {
            "id": keyword.id,
            "value": keyword.value,
            "type": keyword.type.value,
            "description": keyword.description,
            "is_enabled": keyword.is_enabled,
            "case_sensitive": keyword.case_sensitive,
            "watchlist_id": keyword.watchlist_id,
            "tags_json": json.dumps(keyword.tags),
            "match_count": keyword.match_count,
            "last_match": keyword.last_match,
            "metadata_json": json.dumps(keyword.metadata),
            "created_at": keyword.created_at,
            "updated_at": keyword.updated_at,
        }
        if existing:
            for k, v in data.items():
                setattr(existing, k, v)
        else:
            self._session.add(KeywordModel(**data))

    async def get_by_id(self, keyword_id: str) -> Keyword | None:
        m = await self._session.get(KeywordModel, keyword_id)
        return self._to_entity(m) if m else None

    async def list_enabled(self) -> list[Keyword]:
        q = select(KeywordModel).where(KeywordModel.is_enabled == True)  # noqa: E712
        r = await self._session.execute(q)
        return [self._to_entity(m) for m in r.scalars().all()]

    async def list_all(self) -> list[Keyword]:
        r = await self._session.execute(select(KeywordModel))
        return [self._to_entity(m) for m in r.scalars().all()]

    async def delete(self, keyword_id: str) -> None:
        m = await self._session.get(KeywordModel, keyword_id)
        if m:
            await self._session.delete(m)

    def _to_entity(self, m: KeywordModel) -> Keyword:
        return Keyword(
            id=m.id,
            value=m.value,
            type=KeywordType(m.type),
            description=m.description,
            is_enabled=m.is_enabled,
            case_sensitive=m.case_sensitive,
            watchlist_id=m.watchlist_id,
            tags=json.loads(m.tags_json or "[]"),
            match_count=m.match_count,
            last_match=m.last_match,
            metadata=json.loads(m.metadata_json or "{}"),
            created_at=m.created_at,
            updated_at=m.updated_at,
        )


class SQLAlchemyVIPRepository(IVIPRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, vip: VIP) -> None:
        existing = await self._session.get(VIPModel, vip.id)
        data = {
            "id": vip.id,
            "name": vip.name,
            "type": vip.type.value,
            "description": vip.description,
            "organization": vip.organization,
            "role": vip.role,
            "is_enabled": vip.is_enabled,
            "emails_json": json.dumps(vip.emails),
            "aliases_json": json.dumps(vip.aliases),
            "domains_json": json.dumps(vip.domains),
            "social_handles_json": json.dumps(vip.social_handles),
            "phones_json": json.dumps(vip.phones),
            "tags_json": json.dumps(vip.tags),
            "alert_on_mention": vip.alert_on_mention,
            "match_count": vip.match_count,
            "last_match": vip.last_match,
            "metadata_json": json.dumps(vip.metadata),
            "created_at": vip.created_at,
            "updated_at": vip.updated_at,
        }
        if existing:
            for k, v in data.items():
                setattr(existing, k, v)
        else:
            self._session.add(VIPModel(**data))

    async def get_by_id(self, vip_id: str) -> VIP | None:
        m = await self._session.get(VIPModel, vip_id)
        return self._to_entity(m) if m else None

    async def list_enabled(self) -> list[VIP]:
        q = select(VIPModel).where(VIPModel.is_enabled == True)  # noqa: E712
        r = await self._session.execute(q)
        return [self._to_entity(m) for m in r.scalars().all()]

    async def list_all(self) -> list[VIP]:
        r = await self._session.execute(select(VIPModel))
        return [self._to_entity(m) for m in r.scalars().all()]

    async def delete(self, vip_id: str) -> None:
        m = await self._session.get(VIPModel, vip_id)
        if m:
            await self._session.delete(m)

    def _to_entity(self, m: VIPModel) -> VIP:
        return VIP(
            id=m.id,
            name=m.name,
            type=VIPType(m.type),
            description=m.description,
            organization=m.organization,
            role=m.role,
            is_enabled=m.is_enabled,
            emails=json.loads(m.emails_json or "[]"),
            aliases=json.loads(m.aliases_json or "[]"),
            domains=json.loads(m.domains_json or "[]"),
            social_handles=json.loads(m.social_handles_json or "{}"),
            phones=json.loads(m.phones_json or "[]"),
            tags=json.loads(m.tags_json or "[]"),
            alert_on_mention=m.alert_on_mention,
            match_count=m.match_count,
            last_match=m.last_match,
            metadata=json.loads(m.metadata_json or "{}"),
            created_at=m.created_at,
            updated_at=m.updated_at,
        )


class SQLAlchemyThreatActorRepository(IThreatActorRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, actor: ThreatActor) -> None:
        existing = await self._session.get(ThreatActorModel, actor.id)
        data = {
            "id": actor.id,
            "name": actor.name,
            "aliases_json": json.dumps(actor.aliases),
            "description": actor.description,
            "motivation_json": json.dumps(actor.motivation),
            "capability": actor.capability,
            "country": actor.country,
            "sectors_targeted_json": json.dumps(actor.sectors_targeted),
            "ttps_json": json.dumps(actor.ttps),
            "associated_indicators_json": json.dumps(actor.associated_indicators),
            "associated_campaigns_json": json.dumps(actor.associated_campaigns),
            "first_seen": actor.first_seen,
            "last_seen": actor.last_seen,
            "tags_json": json.dumps(actor.tags),
            "references_json": json.dumps(actor.references),
            "metadata_json": json.dumps(actor.metadata),
            "created_at": actor.created_at,
            "updated_at": actor.updated_at,
        }
        if existing:
            for k, v in data.items():
                setattr(existing, k, v)
        else:
            self._session.add(ThreatActorModel(**data))

    async def get_by_id(self, actor_id: str) -> ThreatActor | None:
        m = await self._session.get(ThreatActorModel, actor_id)
        return self._to_entity(m) if m else None

    async def get_by_name(self, name: str) -> ThreatActor | None:
        q = select(ThreatActorModel).where(ThreatActorModel.name == name)
        r = await self._session.execute(q)
        m = r.scalar_one_or_none()
        return self._to_entity(m) if m else None

    async def list_all(self) -> list[ThreatActor]:
        r = await self._session.execute(select(ThreatActorModel))
        return [self._to_entity(m) for m in r.scalars().all()]

    async def delete(self, actor_id: str) -> None:
        m = await self._session.get(ThreatActorModel, actor_id)
        if m:
            await self._session.delete(m)

    def _to_entity(self, m: ThreatActorModel) -> ThreatActor:
        return ThreatActor(
            id=m.id,
            name=m.name,
            aliases=json.loads(m.aliases_json or "[]"),
            description=m.description,
            motivation=json.loads(m.motivation_json or "[]"),
            capability=m.capability,
            country=m.country,
            sectors_targeted=json.loads(m.sectors_targeted_json or "[]"),
            ttps=json.loads(m.ttps_json or "[]"),
            associated_indicators=json.loads(m.associated_indicators_json or "[]"),
            associated_campaigns=json.loads(m.associated_campaigns_json or "[]"),
            first_seen=m.first_seen,
            last_seen=m.last_seen,
            tags=json.loads(m.tags_json or "[]"),
            references=json.loads(m.references_json or "[]"),
            metadata=json.loads(m.metadata_json or "{}"),
            created_at=m.created_at,
            updated_at=m.updated_at,
        )


class SQLAlchemyRuleRepository(IRuleRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, rule: Rule) -> None:
        existing = await self._session.get(RuleModel, rule.id)
        data = {
            "id": rule.id,
            "name": rule.name,
            "type": rule.type.value,
            "description": rule.description,
            "pattern": rule.pattern,
            "content": rule.content,
            "ioc_list_json": json.dumps(rule.ioc_list),
            "sub_rules_json": json.dumps(rule.sub_rules),
            "operator": rule.operator.value,
            "is_enabled": rule.is_enabled,
            "priority": rule.priority,
            "confidence": rule.confidence,
            "score_contribution": rule.score_contribution,
            "categories_json": json.dumps(rule.categories),
            "tags_json": json.dumps(rule.tags),
            "match_count": rule.match_count,
            "false_positive_count": rule.false_positive_count,
            "last_match": rule.last_match,
            "metadata_json": json.dumps(rule.metadata),
            "author": rule.author,
            "version": rule.version,
            "references_json": json.dumps(rule.references),
            "created_at": rule.created_at,
            "updated_at": rule.updated_at,
        }
        if existing:
            for k, v in data.items():
                setattr(existing, k, v)
        else:
            self._session.add(RuleModel(**data))

    async def get_by_id(self, rule_id: str) -> Rule | None:
        m = await self._session.get(RuleModel, rule_id)
        return self._to_entity(m) if m else None

    async def list_enabled(self, rule_type: str | None = None) -> list[Rule]:
        q = select(RuleModel).where(RuleModel.is_enabled == True)  # noqa: E712
        if rule_type:
            q = q.where(RuleModel.type == rule_type)
        q = q.order_by(RuleModel.priority.desc())
        r = await self._session.execute(q)
        return [self._to_entity(m) for m in r.scalars().all()]

    async def list_all(self) -> list[Rule]:
        r = await self._session.execute(select(RuleModel).order_by(RuleModel.priority.desc()))
        return [self._to_entity(m) for m in r.scalars().all()]

    async def delete(self, rule_id: str) -> None:
        m = await self._session.get(RuleModel, rule_id)
        if m:
            await self._session.delete(m)

    def _to_entity(self, m: RuleModel) -> Rule:
        return Rule(
            id=m.id,
            name=m.name,
            type=RuleType(m.type),
            description=m.description,
            pattern=m.pattern,
            content=m.content,
            ioc_list=json.loads(m.ioc_list_json or "[]"),
            sub_rules=json.loads(m.sub_rules_json or "[]"),
            operator=CompositeOperator(m.operator),
            is_enabled=m.is_enabled,
            priority=m.priority,
            confidence=m.confidence,
            score_contribution=m.score_contribution,
            categories=json.loads(m.categories_json or "[]"),
            tags=json.loads(m.tags_json or "[]"),
            match_count=m.match_count,
            false_positive_count=m.false_positive_count,
            last_match=m.last_match,
            metadata=json.loads(m.metadata_json or "{}"),
            author=m.author,
            version=m.version,
            references=json.loads(m.references_json or "[]"),
            created_at=m.created_at,
            updated_at=m.updated_at,
        )


class SQLAlchemyConnectorConfigRepository(IConnectorConfigRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, config: ConnectorConfig) -> None:
        existing = await self._session.get(ConnectorConfigModel, config.id)
        data = {
            "id": config.id,
            "connector_id": config.connector_id,
            "name": config.name,
            "source_type": config.source_type.value,
            "is_enabled": config.is_enabled,
            "opsec_profile": config.opsec_profile,
            "credentials_json": json.dumps(config.credentials),
            "params_json": json.dumps(config.params),
            "tags_json": json.dumps(config.tags),
            "schedule": config.schedule,
            "last_run": config.last_run,
            "last_success": config.last_success,
            "last_error": config.last_error,
            "run_count": config.run_count,
            "error_count": config.error_count,
            "findings_produced": config.findings_produced,
            "created_at": config.created_at,
            "updated_at": config.updated_at,
        }
        if existing:
            for k, v in data.items():
                setattr(existing, k, v)
        else:
            self._session.add(ConnectorConfigModel(**data))

    async def get_by_id(self, config_id: str) -> ConnectorConfig | None:
        m = await self._session.get(ConnectorConfigModel, config_id)
        return self._to_entity(m) if m else None

    async def get_by_connector_id(self, connector_id: str) -> ConnectorConfig | None:
        q = select(ConnectorConfigModel).where(
            ConnectorConfigModel.connector_id == connector_id
        )
        r = await self._session.execute(q)
        m = r.scalar_one_or_none()
        return self._to_entity(m) if m else None

    async def list_enabled(self) -> list[ConnectorConfig]:
        q = select(ConnectorConfigModel).where(ConnectorConfigModel.is_enabled == True)  # noqa: E712
        r = await self._session.execute(q)
        return [self._to_entity(m) for m in r.scalars().all()]

    async def list_all(self) -> list[ConnectorConfig]:
        r = await self._session.execute(select(ConnectorConfigModel))
        return [self._to_entity(m) for m in r.scalars().all()]

    def _to_entity(self, m: ConnectorConfigModel) -> ConnectorConfig:
        return ConnectorConfig(
            id=m.id,
            connector_id=m.connector_id,
            name=m.name,
            source_type=SourceType(m.source_type),
            is_enabled=m.is_enabled,
            opsec_profile=m.opsec_profile,
            credentials=json.loads(m.credentials_json or "{}"),
            params=json.loads(m.params_json or "{}"),
            tags=json.loads(m.tags_json or "[]"),
            schedule=m.schedule,
            last_run=m.last_run,
            last_success=m.last_success,
            last_error=m.last_error,
            run_count=m.run_count,
            error_count=m.error_count,
            findings_produced=m.findings_produced,
            created_at=m.created_at,
            updated_at=m.updated_at,
        )
