"""Unit/integration tests for the persistence layer."""

from __future__ import annotations

import pytest

from phishing_intel.database.repositories import AnalysisRepository
from phishing_intel.database.session import Database, get_db, init_db


def test_save_and_query_by_fingerprint(memory_db: Database, sample_result) -> None:
    with memory_db.session_scope() as session:
        repo = AnalysisRepository(session)
        site = repo.save_analysis(sample_result, campaign_id="CAMP-itau-cccccccccccc")
        assert site.id is not None
        assert site.campaign is not None
        assert site.fingerprint.campaign_fingerprint == "c" * 64

    # New session: verify correlation lookups return the persisted row.
    with memory_db.session_scope() as session:
        repo = AnalysisRepository(session)
        assert len(repo.sites.find_by_fingerprint("c" * 64)) == 1
        assert len(repo.sites.find_by_dom_hash("d" * 64)) == 1
        assert len(repo.sites.find_by_cert_serial("0a1b2c3d")) == 1
        assert len(repo.sites.find_by_asn("AS64500")) == 1
        assert len(repo.sites.find_by_brand("itau")) == 1
        assert repo.sites.find_by_fingerprint("nope") == []


def test_campaign_upsert_updates_last_seen_and_score(memory_db: Database) -> None:
    with memory_db.session_scope() as session:
        repo = AnalysisRepository(session)
        c1 = repo.campaigns.upsert("CAMP-x", score=40, confidence="medium")
        first_seen = c1.first_seen
        # Upsert again with a higher score -> score/confidence updated.
        c2 = repo.campaigns.upsert("CAMP-x", score=90, confidence="high")
        assert c2.campaign_id == c1.campaign_id
        assert c2.score == 90
        assert c2.confidence == "high"
        assert c2.first_seen == first_seen
        assert len(repo.campaigns.list_all()) == 1


def test_misp_event_repository(memory_db: Database) -> None:
    with memory_db.session_scope() as session:
        repo = AnalysisRepository(session)
        repo.misp_events.record("https://x", "uuid-1", "10")
    with memory_db.session_scope() as session:
        repo = AnalysisRepository(session)
        event = repo.misp_events.get_by_uuid("uuid-1")
        assert event is not None
        assert event.event_id == "10"


def test_session_scope_rolls_back_on_error(memory_db: Database) -> None:
    with pytest.raises(ValueError):
        with memory_db.session_scope() as session:
            repo = AnalysisRepository(session)
            repo.campaigns.upsert("CAMP-rollback", score=1)
            raise ValueError("boom")
    # The rolled-back campaign must not have been persisted.
    with memory_db.session_scope() as session:
        repo = AnalysisRepository(session)
        assert repo.campaigns.get_by_campaign_id("CAMP-rollback") is None


def test_init_db_and_get_db_singleton() -> None:
    db = init_db("sqlite:///:memory:")
    assert get_db() is db


def test_get_db_before_init_raises(monkeypatch) -> None:
    import phishing_intel.database.session as session_mod

    monkeypatch.setattr(session_mod, "_DATABASE", None)
    with pytest.raises(RuntimeError):
        session_mod.get_db()


def test_drop_all_and_new_session(memory_db: Database) -> None:
    session = memory_db.new_session()
    session.close()
    memory_db.drop_all()  # should not raise
