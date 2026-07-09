"""Testes dos repositorios de persistencia (database.repositories)."""

from __future__ import annotations

from sqlalchemy.orm import Session

from database.repositories import (
    AuditLogRepository,
    CampaignRepository,
    CertificateRepository,
    EvidenceRepository,
    FingerprintRepository,
    InfrastructureRepository,
    MispEventRepository,
    PhishingSiteRepository,
    ProfileComparisonRepository,
)


def test_campaign_repository_create_and_lookup(db_session: Session) -> None:
    repo = CampaignRepository(db_session)
    created = repo.create(campaign_id="CAMP-1", score=80.0, confidence="high", target_brand="itau")

    fetched = repo.get_by_campaign_id("CAMP-1")
    assert fetched is not None
    assert fetched.id == created.id
    assert fetched.target_brand == "itau"

    assert repo.get_by_campaign_id("MISSING") is None


def test_campaign_repository_update_score(db_session: Session) -> None:
    repo = CampaignRepository(db_session)
    campaign = repo.create(campaign_id="CAMP-2", score=10.0, confidence="low")

    repo.update_score(campaign, score=75.0, confidence="high")

    fetched = repo.get_by_campaign_id("CAMP-2")
    assert fetched.score == 75.0
    assert fetched.confidence == "high"


def test_certificate_repository_get_or_create_avoids_duplicates(db_session: Session) -> None:
    repo = CertificateRepository(db_session)
    cert1 = repo.get_or_create(
        subject="CN=phish.example",
        issuer="CN=Evil CA",
        serial_number="123",
        sha1_fingerprint="a" * 40,
        sha256_fingerprint="b" * 64,
    )
    cert2 = repo.get_or_create(
        subject="CN=phish.example",
        issuer="CN=Evil CA",
        serial_number="123",
        sha1_fingerprint="a" * 40,
        sha256_fingerprint="b" * 64,
    )
    assert cert1.id == cert2.id


def test_fingerprint_repository_find_by_campaign_fingerprint(db_session: Session) -> None:
    repo = FingerprintRepository(db_session)
    repo.create(dom_hash="dom1", asset_hash="asset1", script_hash="script1", campaign_fingerprint="camp_fp_1")
    repo.create(dom_hash="dom2", asset_hash="asset2", script_hash="script2", campaign_fingerprint="camp_fp_2")

    matches = repo.find_by_campaign_fingerprint("camp_fp_1")
    assert len(matches) == 1
    assert matches[0].dom_hash == "dom1"

    dom_matches = repo.find_by_dom_hash("dom2")
    assert len(dom_matches) == 1


def test_infrastructure_repository_find_by_asn(db_session: Session) -> None:
    repo = InfrastructureRepository(db_session)
    repo.create(ip="203.0.113.10", asn="AS64500", provider="evil-hosting", domain="phish.example", country="NL")
    repo.create(ip="203.0.113.11", asn="AS64500", provider="evil-hosting", domain="phish2.example", country="NL")
    repo.create(ip="203.0.113.12", asn="AS99999", provider="other", domain="phish3.example", country="US")

    matches = repo.find_by_asn("AS64500")
    assert len(matches) == 2

    provider_matches = repo.find_by_provider("evil-hosting")
    assert len(provider_matches) == 2


def test_phishing_site_repository_relationships(db_session: Session) -> None:
    fingerprint_repo = FingerprintRepository(db_session)
    site_repo = PhishingSiteRepository(db_session)

    fingerprint = fingerprint_repo.create("dom", "asset", "script", "campfp")
    site = site_repo.create(
        url="https://phish.example/login",
        domain="phish.example",
        html_hash="h1",
        javascript_hash="j1",
        phishing_type="credential_harvesting",
        target_brand="itau",
        fingerprint_id=fingerprint.id,
    )

    by_domain = site_repo.find_by_domain("phish.example")
    assert len(by_domain) == 1
    assert by_domain[0].id == site.id

    by_brand = site_repo.find_by_target_brand("itau")
    assert len(by_brand) == 1

    by_fp = site_repo.find_by_fingerprint_id(fingerprint.id)
    assert len(by_fp) == 1


def test_misp_event_repository_create_and_lookup(db_session: Session) -> None:
    repo = MispEventRepository(db_session)
    event = repo.create(event_uuid="uuid-123", event_id="42", campaign_id=None)

    fetched = repo.get_by_event_uuid("uuid-123")
    assert fetched is not None
    assert fetched.id == event.id


def test_evidence_repository_create_and_list(db_session: Session) -> None:
    site_repo = PhishingSiteRepository(db_session)
    site = site_repo.create(
        url="https://phish.example/login",
        domain="phish.example",
        html_hash="h1",
        javascript_hash="j1",
        phishing_type="credential_harvesting",
        target_brand=None,
    )
    evidence_repo = EvidenceRepository(db_session)
    evidence_repo.create(
        url=site.url,
        site_id=site.id,
        html_sha256="h1",
        javascript_sha256="j1",
        ssl_sha256_fingerprint=None,
        source="partner_supplied",
    )

    records = evidence_repo.list_for_site(site.id)
    assert len(records) == 1
    assert records[0].html_sha256 == "h1"


def test_profile_comparison_repository_serializes_diffs(db_session: Session) -> None:
    repo = ProfileComparisonRepository(db_session)
    comparison = repo.create(
        site_id=None,
        baseline_profile="desktop_chrome",
        compared_profile="iphone_safari",
        dom_differs=True,
        assets_diff=["/a.png"],
        scripts_diff=["/b.js"],
    )
    assert comparison.assets_diff == '["/a.png"]'


def test_audit_log_repository_log_and_list_recent(db_session: Session) -> None:
    repo = AuditLogRepository(db_session)
    repo.log(action="analysis_completed", url="https://phish.example", details={"score": 80})

    recent = repo.list_recent(limit=10)
    assert len(recent) == 1
    assert recent[0].action == "analysis_completed"
