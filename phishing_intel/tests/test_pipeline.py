"""Integration tests for the end-to-end pipeline (offline)."""

from __future__ import annotations

from pathlib import Path

from phishing_intel.models.findings import PhishingSample, PhishingType
from phishing_intel.pipeline import PhishingIntelPipeline


def test_analyze_offline(settings, phishing_html: str, tmp_path: Path) -> None:
    settings.app.evidence_dir = str(tmp_path)
    pipeline = PhishingIntelPipeline(settings)
    sample = PhishingSample(url="https://itau-secure.example/login", html=phishing_html)
    result = pipeline.analyze(sample)

    assert result.domain == "itau-secure.example"
    assert result.classification.primary_type == PhishingType.CREDENTIAL_HARVESTING
    assert result.brand.target_brand == "itau"
    assert result.fingerprint.campaign_fingerprint
    # Exfiltration should surface the telegram + collector endpoints.
    channels = {d.channel.value for d in result.exfiltration.destinations}
    assert "messaging" in channels
    # No network -> no live certificate/infrastructure.
    assert result.certificate is None
    assert result.infrastructure is None
    assert result.iocs


def test_process_persists_and_correlates(settings, phishing_html: str, memory_db, tmp_path: Path) -> None:
    settings.app.evidence_dir = str(tmp_path)
    pipeline = PhishingIntelPipeline(settings, database=memory_db)

    first = PhishingSample(url="https://itau-a.example/login", html=phishing_html)
    outcome1 = pipeline.process(first)
    assert outcome1.attribution.score == 0  # no history yet
    assert Path(outcome1.evidence_path).exists()

    # Second, same-kit sample must correlate to high confidence.
    variant = phishing_html.replace("next.php", "gate.php")
    second = PhishingSample(url="https://itau-b.example/entrar", html=variant)
    outcome2 = pipeline.process(second)
    assert outcome2.attribution.score >= 70
    assert outcome2.campaign_id is not None
    assert any(t.startswith("fraude:") for t in outcome2.tags)


def test_process_without_db(settings, phishing_html: str, tmp_path: Path) -> None:
    settings.app.evidence_dir = str(tmp_path)
    pipeline = PhishingIntelPipeline(settings, database=None)
    outcome = pipeline.process(
        PhishingSample(url="https://x.example", html=phishing_html)
    )
    # No DB -> default (empty) attribution but analysis + evidence still run.
    assert outcome.attribution.score == 0
    assert outcome.result.brand.target_brand == "itau"


def test_secondary_flow_fetches_html_when_missing(settings, phishing_html: str, tmp_path: Path, mocker) -> None:
    settings.app.evidence_dir = str(tmp_path)
    settings.app.allow_network = True
    html_collector = mocker.Mock()
    html_collector.collect.return_value = phishing_html
    html_collector.collect_profiles.return_value = {}
    ssl_collector = mocker.Mock()
    ssl_collector.collect.return_value = None
    infra_collector = mocker.Mock()
    infra_collector.collect.return_value = None

    pipeline = PhishingIntelPipeline(
        settings,
        html_collector=html_collector,
        ssl_collector=ssl_collector,
        infrastructure_collector=infra_collector,
    )
    # No HTML supplied -> the collector's fetch is used.
    result = pipeline.analyze(PhishingSample(url="https://itau.example/login"))
    html_collector.collect.assert_called_once()
    assert result.brand.target_brand == "itau"


def test_misp_push_recorded(settings, phishing_html: str, memory_db, tmp_path: Path, mocker) -> None:
    settings.app.evidence_dir = str(tmp_path)
    misp = mocker.Mock()
    misp.push.return_value = ("evt-uuid", "5")
    pipeline = PhishingIntelPipeline(settings, database=memory_db, misp_enricher=misp)
    outcome = pipeline.process(
        PhishingSample(url="https://itau.example/login", html=phishing_html)
    )
    assert outcome.misp_event_uuid == "evt-uuid"
    # The MISP event reference must be persisted.
    from phishing_intel.database.repositories import AnalysisRepository

    with memory_db.session_scope() as session:
        assert AnalysisRepository(session).misp_events.get_by_uuid("evt-uuid") is not None
