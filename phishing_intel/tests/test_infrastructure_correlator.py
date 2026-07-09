"""Testes do correlacionador por infraestrutura (correlators.infrastructure_correlator)."""

from __future__ import annotations

from sqlalchemy.orm import Session

from correlators.infrastructure_correlator import correlate_by_infrastructure
from database.repositories import InfrastructureRepository, PhishingSiteRepository
from models.campaign import CorrelationSignalType
from models.findings import InfrastructureFinding


def test_correlate_by_infrastructure_finds_shared_asn(db_session: Session) -> None:
    infra_repo = InfrastructureRepository(db_session)
    site_repo = PhishingSiteRepository(db_session)

    infra = infra_repo.create(ip="203.0.113.10", asn="AS64500", provider="evil-hosting", domain="old.example", country="NL")
    site_repo.create(
        url="https://old.example/login",
        domain="old.example",
        html_hash="h",
        javascript_hash="j",
        phishing_type="credential_harvesting",
        target_brand=None,
        infrastructure_id=infra.id,
    )

    new_infrastructure = InfrastructureFinding(domain="new.example", ip="203.0.113.99", asn="AS64500")
    signals = correlate_by_infrastructure(new_infrastructure, infra_repo, site_repo)

    assert len(signals) == 1
    assert signals[0].signal_type == CorrelationSignalType.SAME_ASN
    assert signals[0].related_site_url == "https://old.example/login"


def test_correlate_by_infrastructure_finds_shared_hosting_provider(db_session: Session) -> None:
    infra_repo = InfrastructureRepository(db_session)
    site_repo = PhishingSiteRepository(db_session)

    infra = infra_repo.create(
        ip="203.0.113.20", asn="AS70000", provider="bulletproof-hosting", domain="old2.example", country="RU"
    )
    site_repo.create(
        url="https://old2.example/login",
        domain="old2.example",
        html_hash="h",
        javascript_hash="j",
        phishing_type="credential_harvesting",
        target_brand=None,
        infrastructure_id=infra.id,
    )

    new_infrastructure = InfrastructureFinding(domain="new2.example", hosting_provider="bulletproof-hosting")
    signals = correlate_by_infrastructure(new_infrastructure, infra_repo, site_repo)

    assert len(signals) == 1
    assert signals[0].signal_type == CorrelationSignalType.SAME_HOSTING_PROVIDER
    assert signals[0].related_site_url == "https://old2.example/login"


def test_correlate_by_infrastructure_no_asn_returns_empty(db_session: Session) -> None:
    infra_repo = InfrastructureRepository(db_session)
    site_repo = PhishingSiteRepository(db_session)

    new_infrastructure = InfrastructureFinding(domain="new.example")
    signals = correlate_by_infrastructure(new_infrastructure, infra_repo, site_repo)
    assert signals == []
