"""Modelos ORM (SQLAlchemy 2.0) do historico de campanhas de phishing.

Responsabilidade do componente
-------------------------------
Definir o esquema relacional que persiste: campanhas, sites de phishing
individuais, certificados TLS, infraestrutura de rede, fingerprints de kit,
eventos MISP associados, comparacoes multi-perfil e a trilha de auditoria/
evidencias (chain of custody) exigida em operacoes profissionais de CTI.

Fluxo de execucao
------------------
As tabelas abaixo sao criadas via Alembic (`alembic/`) ou, em ambientes de
avaliacao/teste, via ``Base.metadata.create_all`` (ver ``database/session.py``).
Os repositorios em ``database/repositories.py`` sao o unico ponto de acesso
de leitura/escrita permitido pelo restante da aplicacao.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _utcnow() -> datetime:
    """Retorna o timestamp atual em UTC, usado como default de auditoria."""
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    """Base declarativa compartilhada por todos os modelos ORM."""


class Campaign(Base):
    """Agrupamento logico de incidentes de phishing correlacionados.

    Regra de negocio: ``score``/``confidence`` refletem o Attribution Score
    mais recente calculado pelo ``campaign_correlator`` para o cluster.
    """

    __tablename__ = "campaigns"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    campaign_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    confidence: Mapped[str] = mapped_column(String(16), default="low", nullable=False)
    target_brand: Mapped[str | None] = mapped_column(String(128), nullable=True)
    phishing_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    kit_fingerprint: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )

    sites: Mapped[list["PhishingSite"]] = relationship(back_populates="campaign")
    misp_events: Mapped[list["MispEvent"]] = relationship(back_populates="campaign")


class Certificate(Base):
    """Certificado X.509 observado em um endpoint de phishing (via TLS)."""

    __tablename__ = "certificates"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    serial_number: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    issuer: Mapped[str] = mapped_column(String(512), nullable=False)
    subject: Mapped[str] = mapped_column(String(512), nullable=False)
    sha1_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    san: Mapped[str | None] = mapped_column(Text, nullable=True)
    not_before: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    not_after: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    raw_pem: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    sites: Mapped[list["PhishingSite"]] = relationship(back_populates="certificate")


class Infrastructure(Base):
    """Dados de infraestrutura de rede (IP/ASN/provedor/pais) de um site."""

    __tablename__ = "infrastructures"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    asn: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    provider: Mapped[str | None] = mapped_column(String(255), nullable=True)
    domain: Mapped[str | None] = mapped_column(String(255), nullable=True)
    country: Mapped[str | None] = mapped_column(String(8), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    sites: Mapped[list["PhishingSite"]] = relationship(back_populates="infrastructure")


class Fingerprint(Base):
    """Fingerprint criptografico de um kit de phishing (DOM/assets/scripts)."""

    __tablename__ = "fingerprints"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    dom_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    asset_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    script_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    campaign_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    sites: Mapped[list["PhishingSite"]] = relationship(back_populates="fingerprint")


class PhishingSite(Base):
    """Um incidente individual: uma URL de phishing analisada em um dado instante."""

    __tablename__ = "phishing_sites"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    url: Mapped[str] = mapped_column(String(2048), nullable=False, index=True)
    domain: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    html_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    javascript_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    phishing_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    target_brand: Mapped[str | None] = mapped_column(String(128), nullable=True)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    campaign_id: Mapped[int | None] = mapped_column(ForeignKey("campaigns.id"), nullable=True)
    certificate_id: Mapped[int | None] = mapped_column(ForeignKey("certificates.id"), nullable=True)
    infrastructure_id: Mapped[int | None] = mapped_column(
        ForeignKey("infrastructures.id"), nullable=True
    )
    fingerprint_id: Mapped[int | None] = mapped_column(ForeignKey("fingerprints.id"), nullable=True)

    campaign: Mapped["Campaign | None"] = relationship(back_populates="sites")
    certificate: Mapped["Certificate | None"] = relationship(back_populates="sites")
    infrastructure: Mapped["Infrastructure | None"] = relationship(back_populates="sites")
    fingerprint: Mapped["Fingerprint | None"] = relationship(back_populates="sites")
    evidence_records: Mapped[list["EvidenceRecordModel"]] = relationship(back_populates="site")
    profile_comparisons: Mapped[list["ProfileComparison"]] = relationship(back_populates="site")


class MispEvent(Base):
    """Referencia a um evento MISP criado/atualizado para uma campanha."""

    __tablename__ = "misp_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_uuid: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    event_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    campaign_id: Mapped[int | None] = mapped_column(ForeignKey("campaigns.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    campaign: Mapped["Campaign | None"] = relationship(back_populates="misp_events")


class EvidenceRecordModel(Base):
    """Registro de cadeia de evidencias (chain of custody) de um artefato coletado.

    Regra de negocio (OPSEC): todo artefato bruto (HTML/JS) processado deve
    ter seu hash e timestamp registrados aqui, independentemente de o
    conteudo bruto ter sido fornecido pelo parceiro ou coletado pela
    plataforma (fluxo secundario).
    """

    __tablename__ = "evidence_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    site_id: Mapped[int | None] = mapped_column(ForeignKey("phishing_sites.id"), nullable=True)
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    html_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    javascript_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    ssl_sha256_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source: Mapped[str] = mapped_column(String(32), default="partner_supplied")
    raw_html_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    raw_javascript_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)

    site: Mapped["PhishingSite | None"] = relationship(back_populates="evidence_records")


class ProfileComparison(Base):
    """Resultado persistido da comparacao multi-perfil (desktop x mobile)."""

    __tablename__ = "profile_comparisons"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    site_id: Mapped[int | None] = mapped_column(ForeignKey("phishing_sites.id"), nullable=True)
    baseline_profile: Mapped[str] = mapped_column(String(64), nullable=False)
    compared_profile: Mapped[str] = mapped_column(String(64), nullable=False)
    dom_differs: Mapped[bool] = mapped_column(default=False)
    assets_diff: Mapped[str | None] = mapped_column(Text, nullable=True)
    scripts_diff: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    site: Mapped["PhishingSite | None"] = relationship(back_populates="profile_comparisons")


class AuditLogEntry(Base):
    """Entrada de log de auditoria estruturado (IOC extraido, score, envio MISP)."""

    __tablename__ = "audit_log_entries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    details: Mapped[str | None] = mapped_column(Text, nullable=True)
