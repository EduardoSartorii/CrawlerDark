"""Testes da camada de persistência (sessão e repositórios)."""

from __future__ import annotations

import pytest

from phishing_intel.database.models import (
    CertificateORM,
    FingerprintORM,
    InfrastructureORM,
    MispEventORM,
    PhishingSiteORM,
)
from phishing_intel.database.repositories import RepositoryBundle


def test_session_scope_commits(database):
    """O context manager deve confirmar a transação ao sair normalmente."""
    with database.session_scope() as session:
        session.add(PhishingSiteORM(url="http://a", domain="a", html_hash="h1"))
    with database.session_scope() as session:
        repos = RepositoryBundle.from_session(session)
        assert len(repos.sites.all()) == 1


def test_session_scope_rolls_back(database):
    """Uma exceção dentro do escopo deve reverter a transação."""
    with pytest.raises(RuntimeError):
        with database.session_scope() as session:
            session.add(PhishingSiteORM(url="http://b", domain="b", html_hash="h2"))
            raise RuntimeError("falha")
    with database.session_scope() as session:
        repos = RepositoryBundle.from_session(session)
        assert repos.sites.all() == []


def test_site_repository_find_by_hash(database):
    """A busca por hash de HTML deve agrupar sites idênticos."""
    with database.session_scope() as session:
        repos = RepositoryBundle.from_session(session)
        repos.sites.add(PhishingSiteORM(url="http://a", domain="a", html_hash="dup"))
        repos.sites.add(PhishingSiteORM(url="http://b", domain="b", html_hash="dup"))
    with database.session_scope() as session:
        repos = RepositoryBundle.from_session(session)
        assert len(repos.sites.find_by_html_hash("dup")) == 2


def test_campaign_repository_upsert(database):
    """O upsert deve criar e depois atualizar a mesma campanha."""
    with database.session_scope() as session:
        repos = RepositoryBundle.from_session(session)
        repos.campaigns.upsert("camp-1", 10, "low")
    with database.session_scope() as session:
        repos = RepositoryBundle.from_session(session)
        repos.campaigns.upsert("camp-1", 80, "high", target_brand="itau")
    with database.session_scope() as session:
        repos = RepositoryBundle.from_session(session)
        camp = repos.campaigns.get_by_campaign_id("camp-1")
        assert camp.score == 80
        assert camp.confidence == "high"
        assert camp.target_brand == "itau"


def test_certificate_repository_upsert_is_idempotent(database):
    """Inserir o mesmo certificado duas vezes não deve duplicar."""
    cert = CertificateORM(serial_number="1", fingerprint="fp1")
    with database.session_scope() as session:
        repos = RepositoryBundle.from_session(session)
        repos.certificates.upsert(cert)
    with database.session_scope() as session:
        repos = RepositoryBundle.from_session(session)
        repos.certificates.upsert(CertificateORM(serial_number="1", fingerprint="fp1"))
        assert len(repos.certificates.find_by_fingerprint("fp1")) == 1


def test_infrastructure_and_fingerprint_and_misp(database):
    """Repositórios de infra, fingerprint e MISP devem persistir e consultar."""
    with database.session_scope() as session:
        repos = RepositoryBundle.from_session(session)
        repos.infrastructures.add(InfrastructureORM(ip="1.1.1.1", asn="AS13335"))
        repos.fingerprints.add(FingerprintORM(campaign_fingerprint="cf1"))
        repos.misp_events.add(
            MispEventORM(event_uuid="u1", event_id="1", campaign_fingerprint="cf1")
        )
    with database.session_scope() as session:
        repos = RepositoryBundle.from_session(session)
        assert len(repos.infrastructures.find_by_asn("AS13335")) == 1
        assert len(repos.fingerprints.find_by_campaign_fingerprint("cf1")) == 1
        assert repos.misp_events.find_by_fingerprint("cf1").event_uuid == "u1"
        assert repos.misp_events.find_by_fingerprint("missing") is None
