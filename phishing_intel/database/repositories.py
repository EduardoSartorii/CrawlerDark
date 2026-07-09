"""Repositórios de acesso a dados.

Arquitetura
-----------
Implementa o padrão *Repository*: cada classe encapsula as operações de
persistência de uma entidade, recebendo uma ``Session`` já aberta. Isso
mantém a lógica de negócio desacoplada do ORM e facilita o mock em testes.

Responsabilidade do componente
------------------------------
Prover operações idempotentes de *upsert* e consultas de correlação
(ex.: buscar sites por fingerprint) usadas pelos correlacionadores.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from phishing_intel.database.models import (
    CampaignORM,
    CertificateORM,
    FingerprintORM,
    InfrastructureORM,
    MispEventORM,
    PhishingSiteORM,
)


class PhishingSiteRepository:
    """Operações de persistência para sites de phishing."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def add(self, site: PhishingSiteORM) -> PhishingSiteORM:
        """Adiciona um site e faz flush para obter o ID gerado.

        Args:
            site: Instância ORM a persistir.

        Returns:
            A mesma instância, agora com ``id`` populado.
        """
        self.session.add(site)
        self.session.flush()
        return site

    def find_by_html_hash(self, html_hash: str) -> list[PhishingSiteORM]:
        """Retorna sites com o mesmo hash de HTML.

        Regra de negócio: HTML idêntico é forte indício de reuso de kit.

        Args:
            html_hash: Hash SHA-256 do HTML.

        Returns:
            Lista de sites correspondentes (possivelmente vazia).
        """
        stmt = select(PhishingSiteORM).where(
            PhishingSiteORM.html_hash == html_hash
        )
        return list(self.session.scalars(stmt))

    def all(self) -> list[PhishingSiteORM]:
        """Retorna todos os sites persistidos."""
        return list(self.session.scalars(select(PhishingSiteORM)))


class CampaignRepository:
    """Operações de persistência para campanhas."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def get_by_campaign_id(self, campaign_id: str) -> CampaignORM | None:
        """Busca uma campanha pelo seu identificador estável.

        Args:
            campaign_id: Identificador derivado do fingerprint composto.

        Returns:
            A campanha, ou ``None`` se ainda não existir.
        """
        stmt = select(CampaignORM).where(CampaignORM.campaign_id == campaign_id)
        return self.session.scalars(stmt).first()

    def upsert(
        self,
        campaign_id: str,
        score: int,
        confidence: str,
        target_brand: str = "",
        phishing_type: str = "",
    ) -> CampaignORM:
        """Cria ou atualiza uma campanha (idempotente).

        Args:
            campaign_id: Identificador estável da campanha.
            score: Attribution Score 0-100.
            confidence: Nível de confiança textual.
            target_brand: Marca-alvo predominante.
            phishing_type: Objetivo predominante.

        Returns:
            A campanha persistida (criada ou atualizada).
        """
        existing = self.get_by_campaign_id(campaign_id)
        if existing is None:
            existing = CampaignORM(campaign_id=campaign_id)
            self.session.add(existing)

        existing.score = score
        existing.confidence = confidence
        existing.target_brand = target_brand
        existing.phishing_type = phishing_type
        self.session.flush()
        return existing


class CertificateRepository:
    """Operações de persistência para certificados SSL/TLS."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def upsert(self, cert: CertificateORM) -> CertificateORM:
        """Insere um certificado se ainda não existir (por serial+fp).

        Args:
            cert: Instância ORM a persistir.

        Returns:
            O certificado existente ou o recém-criado.
        """
        stmt = select(CertificateORM).where(
            CertificateORM.serial_number == cert.serial_number,
            CertificateORM.fingerprint == cert.fingerprint,
        )
        existing = self.session.scalars(stmt).first()
        if existing is not None:
            return existing
        self.session.add(cert)
        self.session.flush()
        return cert

    def find_by_fingerprint(self, fingerprint: str) -> list[CertificateORM]:
        """Retorna certificados com o mesmo fingerprint SHA-256."""
        stmt = select(CertificateORM).where(
            CertificateORM.fingerprint == fingerprint
        )
        return list(self.session.scalars(stmt))


class InfrastructureRepository:
    """Operações de persistência para infraestrutura de hospedagem."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def add(self, infra: InfrastructureORM) -> InfrastructureORM:
        """Adiciona um registro de infraestrutura e faz flush."""
        self.session.add(infra)
        self.session.flush()
        return infra

    def find_by_asn(self, asn: str) -> list[InfrastructureORM]:
        """Retorna registros de infraestrutura com o mesmo ASN."""
        stmt = select(InfrastructureORM).where(InfrastructureORM.asn == asn)
        return list(self.session.scalars(stmt))


class FingerprintRepository:
    """Operações de persistência para fingerprints estruturais."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def add(self, fp: FingerprintORM) -> FingerprintORM:
        """Adiciona um fingerprint e faz flush."""
        self.session.add(fp)
        self.session.flush()
        return fp

    def find_by_campaign_fingerprint(
        self, campaign_fingerprint: str
    ) -> list[FingerprintORM]:
        """Retorna fingerprints com o mesmo hash composto de campanha."""
        stmt = select(FingerprintORM).where(
            FingerprintORM.campaign_fingerprint == campaign_fingerprint
        )
        return list(self.session.scalars(stmt))


class MispEventRepository:
    """Operações de persistência para vínculos com eventos MISP."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def add(self, event: MispEventORM) -> MispEventORM:
        """Registra um evento MISP criado e faz flush."""
        self.session.add(event)
        self.session.flush()
        return event

    def find_by_fingerprint(self, campaign_fingerprint: str) -> MispEventORM | None:
        """Busca um evento MISP já criado para um fingerprint de campanha.

        Regra de negócio: evita criar múltiplos eventos para a mesma
        campanha — se já existe, o pipeline deve atualizar, não recriar.
        """
        stmt = select(MispEventORM).where(
            MispEventORM.campaign_fingerprint == campaign_fingerprint
        )
        return self.session.scalars(stmt).first()


@dataclass
class RepositoryBundle:
    """Agrupa todos os repositórios sobre uma mesma sessão.

    Facilita a injeção de dependências no orquestrador: em vez de instanciar
    cada repositório manualmente, o pipeline recebe um único ``bundle``.
    """

    sites: PhishingSiteRepository
    campaigns: CampaignRepository
    certificates: CertificateRepository
    infrastructures: InfrastructureRepository
    fingerprints: FingerprintRepository
    misp_events: MispEventRepository

    @classmethod
    def from_session(cls, session: Session) -> "RepositoryBundle":
        """Constrói o bundle a partir de uma sessão aberta.

        Args:
            session: Sessão SQLAlchemy ativa.

        Returns:
            Um :class:`RepositoryBundle` com todos os repositórios prontos.
        """
        return cls(
            sites=PhishingSiteRepository(session),
            campaigns=CampaignRepository(session),
            certificates=CertificateRepository(session),
            infrastructures=InfrastructureRepository(session),
            fingerprints=FingerprintRepository(session),
            misp_events=MispEventRepository(session),
        )
