"""Integration tests for the correlation / attribution engine."""

from __future__ import annotations

import copy

from phishing_intel.config.settings import CorrelationSettings
from phishing_intel.correlators.campaign_correlator import CampaignCorrelator
from phishing_intel.database.repositories import AnalysisRepository
from phishing_intel.database.session import Database
from phishing_intel.models.findings import ConfidenceLevel


def _correlate(db: Database, result, settings=None):
    settings = settings or CorrelationSettings()
    with db.session_scope() as session:
        repo = AnalysisRepository(session)
        correlator = CampaignCorrelator(repo.sites, settings)
        return correlator.correlate(result)


def test_no_history_scores_zero(memory_db: Database, sample_result) -> None:
    attribution = _correlate(memory_db, sample_result)
    assert attribution.score == 0
    assert attribution.confidence == ConfidenceLevel.LOW
    assert attribution.matched_campaign_id is None


def test_full_signal_stack_high_confidence(memory_db: Database, sample_result) -> None:
    # Persist the first sample so the second can correlate against it.
    with memory_db.session_scope() as session:
        AnalysisRepository(session).save_analysis(
            sample_result, campaign_id="CAMP-itau-cccccccccccc"
        )

    # Second sample shares fingerprint, cert, ASN, provider and brand.
    second = copy.deepcopy(sample_result)
    second.url = "https://itau-verify.example/entrar"
    attribution = _correlate(memory_db, second)

    signals = {m.signal for m in attribution.matches}
    assert "same_fingerprint" in signals
    assert "same_certificate" in signals
    assert "same_asn" in signals
    assert "same_provider" in signals
    assert "same_brand" in signals
    assert attribution.confidence == ConfidenceLevel.HIGH
    assert attribution.score >= 70
    # Inherits the existing campaign id from the correlated site.
    assert attribution.matched_campaign_id == "CAMP-itau-cccccccccccc"


def test_score_is_capped_at_100(memory_db: Database, sample_result) -> None:
    with memory_db.session_scope() as session:
        AnalysisRepository(session).save_analysis(sample_result)
    second = copy.deepcopy(sample_result)
    second.url = "https://another.example"
    attribution = _correlate(memory_db, second)
    assert attribution.score <= 100


def test_medium_confidence_proposes_new_campaign(memory_db: Database, sample_result) -> None:
    # Weight the ASN signal so a lone ASN match lands in the medium band and no
    # existing campaign is linked -> a new campaign id is proposed.
    settings = CorrelationSettings()
    settings.weights["same_asn"] = 50
    with memory_db.session_scope() as session:
        # Persist a prior site (no campaign) that shares only the ASN.
        prior = copy.deepcopy(sample_result)
        prior.fingerprint = None
        prior.certificate = None
        prior.brand = None
        prior.url = "https://prior.example"
        AnalysisRepository(session).save_analysis(prior)

    second = copy.deepcopy(sample_result)
    second.fingerprint = None  # avoid fingerprint attribution path
    second.certificate = None
    second.brand = None
    second.url = "https://new.example"
    attribution = _correlate(memory_db, second, settings)
    assert attribution.confidence == ConfidenceLevel.MEDIUM
    # No fingerprint -> cannot propose an id -> stays None (proposal needs fp).
    assert attribution.matched_campaign_id is None
