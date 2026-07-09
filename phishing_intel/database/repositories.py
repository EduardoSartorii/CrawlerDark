"""Repositorios de acesso a dados.

Responsabilidade do componente
-------------------------------
Encapsular toda a leitura/escrita no banco relacional atras de uma API
orientada a dominio. Os ``correlators`` consultam o historico exclusivamente
atraves destes repositorios (ex.: "existe algum site com este fingerprint?"),
nunca via SQL/ORM direto — isso mantem a logica de correlacao independente
do motor de persistencia escolhido.

Fluxo de execucao
------------------
Cada repositorio recebe uma ``Session`` SQLAlchemy ja aberta (normalmente
via ``database.session.session_scope``) e a utiliza apenas durante o
metodo chamado, nunca guardando estado entre chamadas.
"""

from __future__ import annotations

import json
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from database.models import (
    AuditLogEntry,
    Campaign,
    Certificate,
    EvidenceRecordModel,
    Fingerprint,
    Infrastructure,
    MispEvent,
    PhishingSite,
    ProfileComparison,
)


class CampaignRepository:
    """Persiste e consulta agrupamentos de campanha."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def get_by_campaign_id(self, campaign_id: str) -> Campaign | None:
        stmt = select(Campaign).where(Campaign.campaign_id == campaign_id)
        return self._session.execute(stmt).scalar_one_or_none()

    def get_by_kit_fingerprint(self, kit_fingerprint: str) -> Campaign | None:
        stmt = select(Campaign).where(Campaign.kit_fingerprint == kit_fingerprint)
        return self._session.execute(stmt).scalars().first()

    def create(
        self,
        campaign_id: str,
        score: float,
        confidence: str,
        target_brand: str | None = None,
        phishing_type: str | None = None,
        kit_fingerprint: str | None = None,
    ) -> Campaign:
        campaign = Campaign(
            campaign_id=campaign_id,
            score=score,
            confidence=confidence,
            target_brand=target_brand,
            phishing_type=phishing_type,
            kit_fingerprint=kit_fingerprint,
        )
        self._session.add(campaign)
        self._session.flush()
        return campaign

    def update_score(self, campaign: Campaign, score: float, confidence: str) -> Campaign:
        campaign.score = score
        campaign.confidence = confidence
        self._session.flush()
        return campaign

    def list_all(self) -> list[Campaign]:
        return list(self._session.execute(select(Campaign)).scalars().all())


class CertificateRepository:
    """Persiste e consulta certificados X.509 observados."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def get_by_fingerprint(self, sha256_fingerprint: str) -> Certificate | None:
        stmt = select(Certificate).where(Certificate.fingerprint == sha256_fingerprint)
        return self._session.execute(stmt).scalars().first()

    def create(
        self,
        subject: str,
        issuer: str,
        serial_number: str,
        sha1_fingerprint: str,
        sha256_fingerprint: str,
        san: list[str] | None = None,
        not_before: datetime | None = None,
        not_after: datetime | None = None,
        raw_pem: str | None = None,
    ) -> Certificate:
        certificate = Certificate(
            subject=subject,
            issuer=issuer,
            serial_number=serial_number,
            sha1_fingerprint=sha1_fingerprint,
            fingerprint=sha256_fingerprint,
            san=json.dumps(san or []),
            not_before=not_before,
            not_after=not_after,
            raw_pem=raw_pem,
        )
        self._session.add(certificate)
        self._session.flush()
        return certificate

    def get_or_create(
        self,
        subject: str,
        issuer: str,
        serial_number: str,
        sha1_fingerprint: str,
        sha256_fingerprint: str,
        san: list[str] | None = None,
        not_before: datetime | None = None,
        not_after: datetime | None = None,
        raw_pem: str | None = None,
    ) -> Certificate:
        existing = self.get_by_fingerprint(sha256_fingerprint)
        if existing is not None:
            return existing
        return self.create(
            subject=subject,
            issuer=issuer,
            serial_number=serial_number,
            sha1_fingerprint=sha1_fingerprint,
            sha256_fingerprint=sha256_fingerprint,
            san=san,
            not_before=not_before,
            not_after=not_after,
            raw_pem=raw_pem,
        )


class InfrastructureRepository:
    """Persiste e consulta dados de infraestrutura de rede."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def find_by_asn(self, asn: str) -> list[Infrastructure]:
        stmt = select(Infrastructure).where(Infrastructure.asn == asn)
        return list(self._session.execute(stmt).scalars().all())

    def find_by_provider(self, provider: str) -> list[Infrastructure]:
        stmt = select(Infrastructure).where(Infrastructure.provider == provider)
        return list(self._session.execute(stmt).scalars().all())

    def create(
        self,
        ip: str | None,
        asn: str | None,
        provider: str | None,
        domain: str | None,
        country: str | None,
    ) -> Infrastructure:
        infra = Infrastructure(ip=ip, asn=asn, provider=provider, domain=domain, country=country)
        self._session.add(infra)
        self._session.flush()
        return infra


class FingerprintRepository:
    """Persiste e consulta fingerprints de kits de phishing."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def find_by_campaign_fingerprint(self, campaign_fingerprint: str) -> list[Fingerprint]:
        stmt = select(Fingerprint).where(Fingerprint.campaign_fingerprint == campaign_fingerprint)
        return list(self._session.execute(stmt).scalars().all())

    def find_by_dom_hash(self, dom_hash: str) -> list[Fingerprint]:
        stmt = select(Fingerprint).where(Fingerprint.dom_hash == dom_hash)
        return list(self._session.execute(stmt).scalars().all())

    def create(
        self, dom_hash: str, asset_hash: str, script_hash: str, campaign_fingerprint: str
    ) -> Fingerprint:
        fingerprint = Fingerprint(
            dom_hash=dom_hash,
            asset_hash=asset_hash,
            script_hash=script_hash,
            campaign_fingerprint=campaign_fingerprint,
        )
        self._session.add(fingerprint)
        self._session.flush()
        return fingerprint


class PhishingSiteRepository:
    """Persiste e consulta incidentes individuais (sites de phishing)."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def find_by_domain(self, domain: str) -> list[PhishingSite]:
        stmt = select(PhishingSite).where(PhishingSite.domain == domain)
        return list(self._session.execute(stmt).scalars().all())

    def find_by_target_brand(self, target_brand: str) -> list[PhishingSite]:
        stmt = select(PhishingSite).where(PhishingSite.target_brand == target_brand)
        return list(self._session.execute(stmt).scalars().all())

    def find_by_fingerprint_id(self, fingerprint_id: int) -> list[PhishingSite]:
        stmt = select(PhishingSite).where(PhishingSite.fingerprint_id == fingerprint_id)
        return list(self._session.execute(stmt).scalars().all())

    def find_by_certificate_id(self, certificate_id: int) -> list[PhishingSite]:
        stmt = select(PhishingSite).where(PhishingSite.certificate_id == certificate_id)
        return list(self._session.execute(stmt).scalars().all())

    def find_by_infrastructure_asn(self, asn: str) -> list[PhishingSite]:
        stmt = (
            select(PhishingSite)
            .join(Infrastructure, PhishingSite.infrastructure_id == Infrastructure.id)
            .where(Infrastructure.asn == asn)
        )
        return list(self._session.execute(stmt).scalars().all())

    def create(
        self,
        url: str,
        domain: str | None,
        html_hash: str | None,
        javascript_hash: str | None,
        phishing_type: str | None,
        target_brand: str | None,
        campaign_id: int | None = None,
        certificate_id: int | None = None,
        infrastructure_id: int | None = None,
        fingerprint_id: int | None = None,
    ) -> PhishingSite:
        site = PhishingSite(
            url=url,
            domain=domain,
            html_hash=html_hash,
            javascript_hash=javascript_hash,
            phishing_type=phishing_type,
            target_brand=target_brand,
            campaign_id=campaign_id,
            certificate_id=certificate_id,
            infrastructure_id=infrastructure_id,
            fingerprint_id=fingerprint_id,
        )
        self._session.add(site)
        self._session.flush()
        return site

    def list_all(self) -> list[PhishingSite]:
        return list(self._session.execute(select(PhishingSite)).scalars().all())


class MispEventRepository:
    """Persiste e consulta referencias a eventos MISP criados."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def get_by_event_uuid(self, event_uuid: str) -> MispEvent | None:
        stmt = select(MispEvent).where(MispEvent.event_uuid == event_uuid)
        return self._session.execute(stmt).scalars().first()

    def get_by_campaign_id(self, campaign_id: int) -> MispEvent | None:
        stmt = select(MispEvent).where(MispEvent.campaign_id == campaign_id)
        return self._session.execute(stmt).scalars().first()

    def create(self, event_uuid: str, event_id: str | None, campaign_id: int | None) -> MispEvent:
        event = MispEvent(event_uuid=event_uuid, event_id=event_id, campaign_id=campaign_id)
        self._session.add(event)
        self._session.flush()
        return event


class EvidenceRepository:
    """Persiste registros de cadeia de evidencias (chain of custody)."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def create(
        self,
        url: str,
        site_id: int | None,
        html_sha256: str | None,
        javascript_sha256: str | None,
        ssl_sha256_fingerprint: str | None,
        source: str,
        raw_html_path: str | None = None,
        raw_javascript_path: str | None = None,
    ) -> EvidenceRecordModel:
        record = EvidenceRecordModel(
            url=url,
            site_id=site_id,
            html_sha256=html_sha256,
            javascript_sha256=javascript_sha256,
            ssl_sha256_fingerprint=ssl_sha256_fingerprint,
            source=source,
            raw_html_path=raw_html_path,
            raw_javascript_path=raw_javascript_path,
        )
        self._session.add(record)
        self._session.flush()
        return record

    def list_for_site(self, site_id: int) -> list[EvidenceRecordModel]:
        stmt = select(EvidenceRecordModel).where(EvidenceRecordModel.site_id == site_id)
        return list(self._session.execute(stmt).scalars().all())


class ProfileComparisonRepository:
    """Persiste resultados de comparacao multi-perfil (desktop x mobile)."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def create(
        self,
        site_id: int | None,
        baseline_profile: str,
        compared_profile: str,
        dom_differs: bool,
        assets_diff: list[str],
        scripts_diff: list[str],
    ) -> ProfileComparison:
        comparison = ProfileComparison(
            site_id=site_id,
            baseline_profile=baseline_profile,
            compared_profile=compared_profile,
            dom_differs=dom_differs,
            assets_diff=json.dumps(assets_diff),
            scripts_diff=json.dumps(scripts_diff),
        )
        self._session.add(comparison)
        self._session.flush()
        return comparison


class AuditLogRepository:
    """Registra eventos de auditoria estruturados (IOCs, scores, envios MISP)."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def log(self, action: str, url: str | None = None, details: dict | None = None) -> AuditLogEntry:
        entry = AuditLogEntry(action=action, url=url, details=json.dumps(details or {}))
        self._session.add(entry)
        self._session.flush()
        return entry

    def list_recent(self, limit: int = 100) -> list[AuditLogEntry]:
        stmt = select(AuditLogEntry).order_by(AuditLogEntry.timestamp.desc()).limit(limit)
        return list(self._session.execute(stmt).scalars().all())
