"""Tests for correlators."""

import tempfile

import pytest

from phishing_intel.correlators.campaign_correlator import CampaignCorrelator
from phishing_intel.correlators.fingerprint_correlator import FingerprintCorrelator
from phishing_intel.correlators.infrastructure_correlator import InfrastructureCorrelator
from phishing_intel.database.repositories import FingerprintRepository
from phishing_intel.database.session import get_session, init_db
from phishing_intel.models.findings import (
    AnalysisResult,
    ConfidenceLevel,
    InfrastructureFinding,
    KitFingerprint,
    SSLCertificate,
)
from phishing_intel.utils import load_config


@pytest.fixture
def config():
    return load_config()


@pytest.fixture
def db():
    with tempfile.NamedTemporaryFile(suffix=".db") as f:
        init_db(f"sqlite:///{f.name}")
        yield f.name


class TestCampaignCorrelator:
    def test_new_incident_low_confidence(self, config, db):
        correlator = CampaignCorrelator(config)
        result = AnalysisResult(url="https://new-evil.com")
        attribution = correlator.correlate(result)
        assert attribution.campaign_id.startswith("CAMP-")
        assert attribution.confidence == ConfidenceLevel.LOW

    def test_fingerprint_match_increases_score(self, config, db):
        correlator = CampaignCorrelator(config)
        fp = KitFingerprint(campaign_fingerprint="known_fp_12345")

        with get_session() as session:
            FingerprintRepository(session).create(
                fp.model_dump(), "https://old-evil.com"
            )

        result = AnalysisResult(
            url="https://new-evil.com",
            kit_fingerprint=fp,
        )
        attribution = correlator.correlate(result)
        assert attribution.score > 0
        assert any(s.signal_type == "fingerprint_match" for s in attribution.signals)

    def test_confidence_classification(self, config):
        correlator = CampaignCorrelator(config)
        assert correlator._classify_confidence(20) == ConfidenceLevel.LOW
        assert correlator._classify_confidence(50) == ConfidenceLevel.MEDIUM
        assert correlator._classify_confidence(80) == ConfidenceLevel.HIGH


class TestFingerprintCorrelator:
    def test_similarity_identical(self):
        correlator = FingerprintCorrelator()
        fp = KitFingerprint(campaign_fingerprint="same")
        assert correlator.similarity_score(fp, fp) == 100.0

    def test_similarity_partial(self):
        correlator = FingerprintCorrelator()
        fp_a = KitFingerprint(dom_hash="abc", script_hash="def", campaign_fingerprint="fp_a")
        fp_b = KitFingerprint(dom_hash="abc", script_hash="xyz", campaign_fingerprint="fp_b")
        score = correlator.similarity_score(fp_a, fp_b)
        assert 0 < score < 100


class TestInfrastructureCorrelator:
    def test_correlate_batch(self, config):
        correlator = InfrastructureCorrelator(config)
        results = [
            AnalysisResult(
                url="https://a.com",
                infrastructure=InfrastructureFinding(ip="1.2.3.4", asn="AS1234"),
            ),
            AnalysisResult(
                url="https://b.com",
                infrastructure=InfrastructureFinding(ip="1.2.3.4", asn="AS1234"),
            ),
        ]
        groups = correlator.correlate_batch(results)
        assert "ip:1.2.3.4" in groups
        assert len(groups["ip:1.2.3.4"]) == 2
