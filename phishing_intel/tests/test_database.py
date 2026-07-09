"""Tests for database layer."""

import tempfile

import pytest

from phishing_intel.database.repositories import (
    CampaignRepository,
    FingerprintRepository,
    PhishingSiteRepository,
    generate_campaign_id,
)
from phishing_intel.database.session import get_session, init_db
from phishing_intel.models.campaign import Campaign
from phishing_intel.models.findings import AnalysisResult, KitFingerprint


@pytest.fixture
def db_session():
    """Create temporary in-memory database for tests."""
    with tempfile.NamedTemporaryFile(suffix=".db") as f:
        init_db(f"sqlite:///{f.name}")
        with get_session() as session:
            yield session


class TestRepositories:
    def test_generate_campaign_id(self):
        cid = generate_campaign_id()
        assert cid.startswith("CAMP-")
        assert len(cid) > 10

    def test_phishing_site_create(self, db_session):
        repo = PhishingSiteRepository(db_session)
        result = AnalysisResult(url="https://evil.com", html_hash="abc123")
        site = repo.create(result)
        assert site.url == "https://evil.com"
        assert site.html_hash == "abc123"

    def test_phishing_site_get_by_url(self, db_session):
        repo = PhishingSiteRepository(db_session)
        result = AnalysisResult(url="https://evil.com", html_hash="abc123")
        repo.create(result)
        found = repo.get_by_url("https://evil.com")
        assert found is not None

    def test_campaign_create(self, db_session):
        repo = CampaignRepository(db_session)
        campaign = Campaign(campaign_id="CAMP-TEST001", target_brand="itau")
        model = repo.create(campaign)
        assert model.campaign_id == "CAMP-TEST001"

    def test_campaign_get_by_id(self, db_session):
        repo = CampaignRepository(db_session)
        campaign = Campaign(campaign_id="CAMP-TEST002")
        repo.create(campaign)
        found = repo.get_by_id("CAMP-TEST002")
        assert found is not None

    def test_campaign_update_score(self, db_session):
        repo = CampaignRepository(db_session)
        campaign = Campaign(campaign_id="CAMP-TEST003")
        repo.create(campaign)
        updated = repo.update_score("CAMP-TEST003", 85.0, "high")
        assert updated.score == 85.0
        assert updated.confidence == "high"

    def test_fingerprint_create(self, db_session):
        repo = FingerprintRepository(db_session)
        fp_data = KitFingerprint(
            dom_hash="abc", campaign_fingerprint="def123"
        ).model_dump()
        model = repo.create(fp_data, "https://evil.com")
        assert model.campaign_fingerprint == "def123"

    def test_fingerprint_get(self, db_session):
        repo = FingerprintRepository(db_session)
        fp_data = KitFingerprint(campaign_fingerprint="unique_fp").model_dump()
        repo.create(fp_data, "https://evil.com")
        found = repo.get_by_campaign_fingerprint("unique_fp")
        assert found is not None
