"""Testes da fabrica de sessao/engine (database.session)."""

from __future__ import annotations

import pytest
from sqlalchemy import inspect

from config.settings import PhishingIntelSettings
from database.session import get_engine, init_db, session_scope
from database.repositories import CampaignRepository


@pytest.fixture()
def sqlite_settings() -> PhishingIntelSettings:
    return PhishingIntelSettings.model_validate(
        {
            "database": {"url": "sqlite:///:memory:", "echo": False},
            "misp": {"url": "https://misp.test", "api_key": "K"},
        }
    )


def test_init_db_creates_all_tables(sqlite_settings: PhishingIntelSettings) -> None:
    init_db(sqlite_settings)
    inspector = inspect(get_engine(sqlite_settings))
    tables = set(inspector.get_table_names())
    assert {"campaigns", "phishing_sites", "certificates", "infrastructures", "fingerprints", "misp_events"}.issubset(
        tables
    )


def test_session_scope_commits_on_success(sqlite_settings: PhishingIntelSettings) -> None:
    init_db(sqlite_settings)
    with session_scope(sqlite_settings) as session:
        CampaignRepository(session).create(campaign_id="CAMP-COMMIT", score=10.0, confidence="low")

    with session_scope(sqlite_settings) as session:
        fetched = CampaignRepository(session).get_by_campaign_id("CAMP-COMMIT")
        assert fetched is not None


def test_session_scope_rolls_back_on_exception(sqlite_settings: PhishingIntelSettings) -> None:
    init_db(sqlite_settings)
    with pytest.raises(ValueError):
        with session_scope(sqlite_settings) as session:
            CampaignRepository(session).create(campaign_id="CAMP-ROLLBACK", score=10.0, confidence="low")
            raise ValueError("simulated failure")

    with session_scope(sqlite_settings) as session:
        fetched = CampaignRepository(session).get_by_campaign_id("CAMP-ROLLBACK")
        assert fetched is None
