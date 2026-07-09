"""
Integration Tests — Repository Layer
========================================

Tests the full storage stack: domain entity → ORM model → database → domain entity.
Uses an in-memory SQLite database (no external dependencies).
"""

from __future__ import annotations

import pytest
import pytest_asyncio

from threat_hunting.core.domain.entities.finding import Finding, FindingStatus
from threat_hunting.core.domain.entities.keyword import Keyword, KeywordType
from threat_hunting.core.domain.entities.vip import VIP, VIPType
from threat_hunting.core.domain.entities.rule import Rule, RuleType
from threat_hunting.core.domain.value_objects.source import SourceType
from threat_hunting.core.domain.value_objects.category import Category
from threat_hunting.core.domain.value_objects.score import Score
from threat_hunting.infrastructure.storage.unit_of_work import SQLAlchemyUnitOfWork


class TestFindingRepository:
    """Integration tests for the SQLAlchemyFindingRepository."""

    @pytest.mark.asyncio
    async def test_save_and_retrieve(self, uow: SQLAlchemyUnitOfWork, sample_finding: Finding):
        async with uow as u:
            await u.findings.save(sample_finding)
            await u.commit()

        async with uow as u:
            retrieved = await u.findings.get_by_id(sample_finding.id)
            assert retrieved is not None
            assert retrieved.id == sample_finding.id
            assert retrieved.title == sample_finding.title
            assert retrieved.source == sample_finding.source
            assert retrieved.connector == sample_finding.connector

    @pytest.mark.asyncio
    async def test_update_finding(self, uow: SQLAlchemyUnitOfWork, sample_finding: Finding):
        async with uow as u:
            await u.findings.save(sample_finding)
            await u.commit()

        sample_finding.set_score(Score.from_raw(8.5, 0.9))
        async with uow as u:
            await u.findings.save(sample_finding)
            await u.commit()

        async with uow as u:
            updated = await u.findings.get_by_id(sample_finding.id)
            assert updated is not None
            assert abs(updated.score.value - 8.5) < 0.01

    @pytest.mark.asyncio
    async def test_list_findings(self, uow: SQLAlchemyUnitOfWork, sample_finding: Finding):
        async with uow as u:
            await u.findings.save(sample_finding)
            await u.commit()

        async with uow as u:
            findings = await u.findings.list(limit=10)
            assert len(findings) >= 1
            assert any(f.id == sample_finding.id for f in findings)

    @pytest.mark.asyncio
    async def test_list_filter_by_connector(self, uow: SQLAlchemyUnitOfWork, sample_finding: Finding):
        async with uow as u:
            await u.findings.save(sample_finding)
            await u.commit()

        async with uow as u:
            findings = await u.findings.list(connector="paste")
            assert all(f.connector == "paste" for f in findings)

        async with uow as u:
            empty = await u.findings.list(connector="nonexistent")
            assert len(empty) == 0

    @pytest.mark.asyncio
    async def test_count(self, uow: SQLAlchemyUnitOfWork, sample_finding: Finding):
        async with uow as u:
            await u.findings.save(sample_finding)
            await u.commit()

        async with uow as u:
            count = await u.findings.count()
            assert count >= 1

    @pytest.mark.asyncio
    async def test_get_nonexistent(self, uow: SQLAlchemyUnitOfWork):
        async with uow as u:
            result = await u.findings.get_by_id("nonexistent-id")
            assert result is None

    @pytest.mark.asyncio
    async def test_delete(self, uow: SQLAlchemyUnitOfWork, sample_finding: Finding):
        async with uow as u:
            await u.findings.save(sample_finding)
            await u.commit()

        async with uow as u:
            await u.findings.delete(sample_finding.id)
            await u.commit()

        async with uow as u:
            result = await u.findings.get_by_id(sample_finding.id)
            assert result is None

    @pytest.mark.asyncio
    async def test_tags_persisted(self, uow: SQLAlchemyUnitOfWork, sample_finding: Finding):
        sample_finding.add_tag("test_tag")
        sample_finding.add_tag("another_tag")
        async with uow as u:
            await u.findings.save(sample_finding)
            await u.commit()

        async with uow as u:
            retrieved = await u.findings.get_by_id(sample_finding.id)
            assert "test_tag" in retrieved.tags
            assert "another_tag" in retrieved.tags

    @pytest.mark.asyncio
    async def test_exists_by_hash(self, uow: SQLAlchemyUnitOfWork, sample_finding: Finding):
        async with uow as u:
            await u.findings.save(sample_finding)
            await u.commit()

        import xxhash
        content_hash = xxhash.xxh64_hexdigest(
            f"{sample_finding.connector}:{sample_finding.source_id or ''}:{sample_finding.title.lower()}"
        )
        async with uow as u:
            exists = await u.findings.exists_by_hash(content_hash)
            assert exists

        async with uow as u:
            not_exists = await u.findings.exists_by_hash("aaaaaaaaaaaaaaaa")
            assert not not_exists


class TestKeywordRepository:
    """Integration tests for the SQLAlchemyKeywordRepository."""

    @pytest.mark.asyncio
    async def test_save_and_retrieve(self, uow: SQLAlchemyUnitOfWork, sample_keyword: Keyword):
        async with uow as u:
            await u.keywords.save(sample_keyword)
            await u.commit()

        async with uow as u:
            retrieved = await u.keywords.get_by_id(sample_keyword.id)
            assert retrieved is not None
            assert retrieved.value == sample_keyword.value

    @pytest.mark.asyncio
    async def test_list_enabled(self, uow: SQLAlchemyUnitOfWork, sample_keyword: Keyword):
        disabled_kw = Keyword(value="disabled keyword", is_enabled=False)
        async with uow as u:
            await u.keywords.save(sample_keyword)
            await u.keywords.save(disabled_kw)
            await u.commit()

        async with uow as u:
            enabled = await u.keywords.list_enabled()
            assert all(k.is_enabled for k in enabled)
            assert any(k.value == sample_keyword.value for k in enabled)
            assert not any(k.value == "disabled keyword" for k in enabled)


class TestVIPRepository:
    """Integration tests for the SQLAlchemyVIPRepository."""

    @pytest.mark.asyncio
    async def test_save_and_retrieve(self, uow: SQLAlchemyUnitOfWork, sample_vip: VIP):
        async with uow as u:
            await u.vips.save(sample_vip)
            await u.commit()

        async with uow as u:
            retrieved = await u.vips.get_by_id(sample_vip.id)
            assert retrieved is not None
            assert retrieved.name == sample_vip.name
            assert "john.ceo@acme.com" in retrieved.emails
            assert "John Smith" in retrieved.aliases

    @pytest.mark.asyncio
    async def test_list_enabled_vips(self, uow: SQLAlchemyUnitOfWork, sample_vip: VIP):
        async with uow as u:
            await u.vips.save(sample_vip)
            await u.commit()

        async with uow as u:
            enabled = await u.vips.list_enabled()
            assert any(v.id == sample_vip.id for v in enabled)


class TestRuleRepository:
    """Integration tests for the SQLAlchemyRuleRepository."""

    @pytest.mark.asyncio
    async def test_save_and_retrieve(self, uow: SQLAlchemyUnitOfWork, sample_rule: Rule):
        async with uow as u:
            await u.rules.save(sample_rule)
            await u.commit()

        async with uow as u:
            retrieved = await u.rules.get_by_id(sample_rule.id)
            assert retrieved is not None
            assert retrieved.name == sample_rule.name
            assert retrieved.pattern == sample_rule.pattern

    @pytest.mark.asyncio
    async def test_list_enabled_by_type(self, uow: SQLAlchemyUnitOfWork, sample_rule: Rule):
        async with uow as u:
            await u.rules.save(sample_rule)
            await u.commit()

        async with uow as u:
            rules = await u.rules.list_enabled(RuleType.REGEX.value)
            assert any(r.id == sample_rule.id for r in rules)

    @pytest.mark.asyncio
    async def test_disabled_rule_not_returned(self, uow: SQLAlchemyUnitOfWork):
        rule = Rule(
            name="Disabled Rule",
            type=RuleType.KEYWORD,
            pattern="test",
            is_enabled=False,
        )
        async with uow as u:
            await u.rules.save(rule)
            await u.commit()

        async with uow as u:
            enabled = await u.rules.list_enabled()
            assert not any(r.id == rule.id for r in enabled)
