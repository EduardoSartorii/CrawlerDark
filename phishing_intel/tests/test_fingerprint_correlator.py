"""Testes do correlacionador por fingerprint (correlators.fingerprint_correlator)."""

from __future__ import annotations

from sqlalchemy.orm import Session

from correlators.fingerprint_correlator import correlate_by_fingerprint
from database.repositories import FingerprintRepository, PhishingSiteRepository
from models.campaign import CorrelationSignalType
from models.findings import KitFingerprint


def test_correlate_by_fingerprint_finds_exact_kit_reuse(db_session: Session) -> None:
    fingerprint_repo = FingerprintRepository(db_session)
    site_repo = PhishingSiteRepository(db_session)

    existing_fp = fingerprint_repo.create(
        dom_hash="dom_shared", asset_hash="asset_shared", script_hash="script_shared", campaign_fingerprint="camp_shared"
    )
    site_repo.create(
        url="https://old-incident.example/login",
        domain="old-incident.example",
        html_hash="h",
        javascript_hash="j",
        phishing_type="credential_harvesting",
        target_brand="itau",
        fingerprint_id=existing_fp.id,
    )

    new_fingerprint = KitFingerprint(
        dom_sha256="dom_shared",
        assets_sha256="asset_shared",
        scripts_sha256="script_shared",
        campaign_fingerprint="camp_shared",
    )

    signals = correlate_by_fingerprint(new_fingerprint, fingerprint_repo, site_repo)

    assert len(signals) == 1
    assert signals[0].signal_type == CorrelationSignalType.SAME_FINGERPRINT
    assert signals[0].related_site_url == "https://old-incident.example/login"


def test_correlate_by_fingerprint_detects_dom_reuse_with_different_scripts(db_session: Session) -> None:
    fingerprint_repo = FingerprintRepository(db_session)
    site_repo = PhishingSiteRepository(db_session)

    existing_fp = fingerprint_repo.create(
        dom_hash="dom_shared", asset_hash="asset_old", script_hash="script_old", campaign_fingerprint="camp_old"
    )
    site_repo.create(
        url="https://old-incident.example/login",
        domain="old-incident.example",
        html_hash="h",
        javascript_hash="j",
        phishing_type="credential_harvesting",
        target_brand="itau",
        fingerprint_id=existing_fp.id,
    )

    new_fingerprint = KitFingerprint(
        dom_sha256="dom_shared",
        assets_sha256="asset_new",
        scripts_sha256="script_new",
        campaign_fingerprint="camp_new",
    )

    signals = correlate_by_fingerprint(new_fingerprint, fingerprint_repo, site_repo)

    signal_types = {signal.signal_type for signal in signals}
    assert CorrelationSignalType.SAME_DOM_PATTERN in signal_types
    assert CorrelationSignalType.SAME_FINGERPRINT not in signal_types


def test_correlate_by_fingerprint_no_history_returns_empty(db_session: Session) -> None:
    fingerprint_repo = FingerprintRepository(db_session)
    site_repo = PhishingSiteRepository(db_session)

    new_fingerprint = KitFingerprint(
        dom_sha256="d", assets_sha256="a", scripts_sha256="s", campaign_fingerprint="c"
    )
    signals = correlate_by_fingerprint(new_fingerprint, fingerprint_repo, site_repo)
    assert signals == []
