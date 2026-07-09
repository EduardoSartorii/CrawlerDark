"""End-to-end pipeline and persistence tests."""

from __future__ import annotations

from pathlib import Path

from phishing_intel.database.models import CampaignORM, FingerprintORM, PhishingSiteORM
from phishing_intel.database.repositories import CampaignRepository
from phishing_intel.database.session import create_session_factory, session_scope
from phishing_intel.models.findings import AnalysisRequest
from phishing_intel.models.infrastructure import InfrastructureFinding
from phishing_intel.pipeline import PhishingIntelPipeline


def test_pipeline_analyzes_persists_and_builds_misp_payload(
    phishing_html: str, phishing_js: str, tmp_path: Path
) -> None:
    """Pipeline handles partner artifacts without network collection."""

    factory = create_session_factory("sqlite:///:memory:")
    with session_scope(factory) as session:
        repository = CampaignRepository(session)
        pipeline = PhishingIntelPipeline(repository=repository, evidence_path=tmp_path)
        result, misp_response = pipeline.analyze(
            AnalysisRequest(
                url="https://phish.example/login",
                html=phishing_html,
                javascript=phishing_js,
                iocs=["https://manual-ioc.example/drop"],
            ),
            infrastructure=InfrastructureFinding(
                domain="phish.example",
                ip="203.0.113.10",
                asn="64500",
                hosting_provider="Example Hosting",
                country="BR",
            ),
        )
        assert result.domain == "phish.example"
        assert result.brand.target_brand == "itau"
        assert result.attribution_score >= 20
        assert result.confidence in {"baixa", "media", "alta"}
        assert "https://manual-ioc.example/drop" in result.extracted_iocs
        assert misp_response and misp_response["dry_run"] is True
        event = misp_response["event"]
        assert "fraude:marca=itau" in event["tags"]
        assert event["objects"][0]["name"] == "phishing-campaign"
        assert (tmp_path / result.campaign_id / "raw.html").exists()
        assert session.query(CampaignORM).count() == 1
        assert session.query(PhishingSiteORM).count() == 1
        assert session.query(FingerprintORM).count() == 1


def test_repository_historical_signals_drive_correlation(phishing_html: str, phishing_js: str, tmp_path: Path) -> None:
    """A second matching incident receives a high score from persisted history."""

    factory = create_session_factory("sqlite:///:memory:")
    with session_scope(factory) as session:
        repository = CampaignRepository(session)
        pipeline = PhishingIntelPipeline(repository=repository, evidence_path=tmp_path)
        request = AnalysisRequest(url="https://phish.example/login", html=phishing_html, javascript=phishing_js)
        first, _ = pipeline.analyze(request, enrich_misp=False)
        second, _ = pipeline.analyze(request, enrich_misp=False)
        assert first.fingerprint.campaign_fingerprint == second.fingerprint.campaign_fingerprint
        assert second.attribution_score >= 80
        assert second.confidence == "alta"
