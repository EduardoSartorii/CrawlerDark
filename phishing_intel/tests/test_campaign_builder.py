"""Testes de integracao do pipeline completo (enrichment.campaign_builder)."""

from __future__ import annotations

from unittest.mock import MagicMock

from pymisp import MISPEvent
from sqlalchemy.orm import Session

from database.models import AuditLogEntry, Campaign, EvidenceRecordModel, PhishingSite
from enrichment.campaign_builder import build_analysis_report, persist_report, run_pipeline
from enrichment.misp_client import MispClient


def test_build_analysis_report_runs_full_analysis_chain(sample_html: str, sample_js: str, test_settings) -> None:
    report = build_analysis_report(
        url="https://phish.example/login",
        html=sample_html,
        javascript=sample_js,
        settings=test_settings,
    )

    assert report.brand.target_brand == "itau"
    assert report.classification.phishing_type.value in {"identity_theft", "credential_harvesting"}
    assert report.fingerprint.campaign_fingerprint
    assert report.evidence.html_sha256 is not None
    assert len(report.exfiltration.destinations) > 0


def test_persist_report_creates_all_related_rows(sample_html: str, sample_js: str, test_settings, db_session: Session) -> None:
    report = build_analysis_report(
        url="https://phish.example/login", html=sample_html, javascript=sample_js, settings=test_settings
    )
    site_id = persist_report(report, db_session)
    db_session.commit()

    site = db_session.get(PhishingSite, site_id)
    assert site is not None
    assert site.domain == "phish.example"
    assert site.fingerprint is not None

    evidence_rows = db_session.query(EvidenceRecordModel).filter_by(site_id=site_id).all()
    assert len(evidence_rows) == 1

    audit_rows = db_session.query(AuditLogEntry).filter_by(action="analysis_completed").all()
    assert len(audit_rows) == 1


def test_run_pipeline_end_to_end_creates_campaign_and_enriches_misp(
    sample_html: str, sample_js: str, test_settings, db_session: Session
) -> None:
    mock_pymisp = MagicMock()
    created_event = MISPEvent()
    created_event.uuid = "misp-event-uuid"
    created_event.id = "1"
    mock_pymisp.add_event.return_value = created_event
    mock_pymisp.add_object.side_effect = lambda event, obj, pythonify=True: obj
    misp_client = MispClient(test_settings.misp, client=mock_pymisp)

    result = run_pipeline(
        url="https://phish.example/login",
        html=sample_html,
        javascript=sample_js,
        session=db_session,
        settings=test_settings,
        misp_client=misp_client,
    )
    db_session.commit()

    assert result.campaign.campaign_id.startswith("CAMP-")
    assert result.misp_event_uuid == "misp-event-uuid"
    assert mock_pymisp.add_event.called
    assert mock_pymisp.add_object.called

    campaigns = db_session.query(Campaign).all()
    assert len(campaigns) == 1


def test_run_pipeline_second_incident_reusing_kit_correlates_to_same_campaign(
    sample_html: str, sample_js: str, test_settings, db_session: Session
) -> None:
    first = run_pipeline(
        url="https://site-one.example/login",
        html=sample_html,
        javascript=sample_js,
        session=db_session,
        settings=test_settings,
        misp_client=None,
    )
    db_session.commit()

    second = run_pipeline(
        url="https://site-two.example/login",
        html=sample_html,
        javascript=sample_js,
        session=db_session,
        settings=test_settings,
        misp_client=None,
    )
    db_session.commit()

    assert second.attribution.score >= test_settings.correlation.weights.same_fingerprint
    assert second.campaign.campaign_id == first.campaign.campaign_id


def test_run_pipeline_without_misp_client_skips_enrichment(
    sample_html: str, sample_js: str, test_settings, db_session: Session
) -> None:
    result = run_pipeline(
        url="https://phish.example/login",
        html=sample_html,
        javascript=sample_js,
        session=db_session,
        settings=test_settings,
        misp_client=None,
    )
    assert result.misp_event_uuid is None
