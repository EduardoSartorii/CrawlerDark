"""Testes do motor de correlação e Attribution Score."""

from __future__ import annotations

from phishing_intel.correlators import (
    CampaignCorrelator,
    CorrelationInput,
    FingerprintCorrelator,
    InfrastructureCorrelator,
)
from phishing_intel.database.models import (
    CertificateORM,
    FingerprintORM,
    InfrastructureORM,
)
from phishing_intel.database.repositories import RepositoryBundle
from phishing_intel.models.campaign import ConfidenceLevel, FingerprintBundle
from phishing_intel.models.findings import AnalysisResult, BrandDetection, PhishingType
from phishing_intel.models.infrastructure import CertificateInfo, InfrastructureInfo


def _make_correlator(session):
    """Constrói o CampaignCorrelator sobre uma sessão de teste."""
    repos = RepositoryBundle.from_session(session)
    return CampaignCorrelator(
        FingerprintCorrelator(repos.fingerprints),
        InfrastructureCorrelator(repos.infrastructures, repos.certificates),
    )


def test_low_confidence_for_new_site(database):
    """Um site novo, sem histórico, deve ter score baixo."""
    with database.session_scope() as session:
        correlator = _make_correlator(session)
        data = CorrelationInput(
            analysis=AnalysisResult(url="http://x", domain="x"),
            fingerprint=FingerprintBundle(campaign_fingerprint="fresh"),
        )
        campaign = correlator.correlate(data)
        assert campaign.confidence == ConfidenceLevel.LOW
        assert campaign.score < 40


def test_high_confidence_with_all_signals(database):
    """Fingerprint + certificado + ASN + provedor + marca => alta confiança."""
    with database.session_scope() as session:
        repos = RepositoryBundle.from_session(session)
        # Semeia histórico para casar todos os sinais.
        repos.fingerprints.add(FingerprintORM(campaign_fingerprint="reused"))
        repos.certificates.upsert(CertificateORM(serial_number="1", fingerprint="fp"))
        repos.infrastructures.add(InfrastructureORM(ip="1.1.1.1", asn="AS100"))
        session.flush()

        correlator = _make_correlator(session)
        data = CorrelationInput(
            analysis=AnalysisResult(
                url="http://x",
                domain="x",
                phishing_types=[PhishingType.CREDENTIAL_HARVESTING],
                brand=BrandDetection(brand="itau", sector="bank", confidence=80),
            ),
            fingerprint=FingerprintBundle(campaign_fingerprint="reused"),
            infrastructure=InfrastructureInfo(
                asn="AS100", hosting_provider="EvilHost"
            ),
            certificate=CertificateInfo(sha256_fingerprint="fp", serial_number="1"),
        )
        campaign = correlator.correlate(data)
        assert campaign.score == 100
        assert campaign.confidence == ConfidenceLevel.HIGH
        assert campaign.target_brand == "itau"
        assert campaign.phishing_type == "credential_harvesting"
        # Todos os sinais devem estar marcados como casados.
        assert all(s.matched for s in campaign.signals)


def test_medium_confidence_partial_signals(database):
    """Apenas fingerprint reincidente => confiança média."""
    with database.session_scope() as session:
        repos = RepositoryBundle.from_session(session)
        repos.fingerprints.add(FingerprintORM(campaign_fingerprint="reused"))
        session.flush()
        correlator = _make_correlator(session)
        data = CorrelationInput(
            analysis=AnalysisResult(url="http://x", domain="x"),
            fingerprint=FingerprintBundle(campaign_fingerprint="reused"),
        )
        campaign = correlator.correlate(data)
        assert campaign.confidence == ConfidenceLevel.MEDIUM


def test_campaign_id_derived_from_fingerprint(database):
    """O campaign_id deve derivar do fingerprint composto (determinístico)."""
    with database.session_scope() as session:
        correlator = _make_correlator(session)
        fp = "a" * 40
        data = CorrelationInput(
            analysis=AnalysisResult(url="http://x"),
            fingerprint=FingerprintBundle(campaign_fingerprint=fp),
        )
        campaign = correlator.correlate(data)
        assert campaign.campaign_id == fp[:32]
