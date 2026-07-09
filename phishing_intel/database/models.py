"""Modelos ORM (SQLAlchemy) da plataforma.

Arquitetura
-----------
Define o esquema relacional que persiste o histórico de campanhas, sites de
phishing, certificados, infraestrutura, fingerprints e eventos MISP.

Responsabilidade do componente
------------------------------
Mapear as entidades de domínio para tabelas, preservando a cadeia de
evidências (hashes, timestamps) para operações profissionais de CTI.

Fluxo de execução
-----------------
As classes ORM são registradas em :data:`Base.metadata`; a criação do
esquema é feita por :class:`phishing_intel.database.session.Database`.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _utcnow() -> datetime:
    """Retorna o instante atual em UTC (timezone-aware).

    Centraliza a geração de timestamps para garantir consistência de fuso
    em toda a camada de persistência (auditoria confiável).
    """
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    """Base declarativa comum a todos os modelos ORM."""


class CampaignORM(Base):
    """Tabela ``campaigns`` — campanhas correlacionadas e atribuídas."""

    __tablename__ = "campaigns"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    # Identificador estável derivado do fingerprint composto.
    campaign_id: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    score: Mapped[int] = mapped_column(Integer, default=0)
    confidence: Mapped[str] = mapped_column(String(16), default="low")
    target_brand: Mapped[str] = mapped_column(String(128), default="")
    phishing_type: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)

    sites: Mapped[list["PhishingSiteORM"]] = relationship(
        back_populates="campaign", cascade="all, delete-orphan"
    )


class PhishingSiteORM(Base):
    """Tabela ``phishing_sites`` — cada artefato/página analisada."""

    __tablename__ = "phishing_sites"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    url: Mapped[str] = mapped_column(String(2048), default="")
    domain: Mapped[str] = mapped_column(String(255), index=True, default="")
    html_hash: Mapped[str] = mapped_column(String(64), index=True, default="")
    js_hash: Mapped[str] = mapped_column(String(64), default="")
    target_brand: Mapped[str] = mapped_column(String(128), default="")
    phishing_type: Mapped[str] = mapped_column(String(64), default="")
    # Caminho da evidência bruta armazenada (HTML/JS) — cadeia de custódia.
    evidence_path: Mapped[str] = mapped_column(String(1024), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)

    campaign_id: Mapped[int | None] = mapped_column(
        ForeignKey("campaigns.id"), nullable=True, index=True
    )
    campaign: Mapped[CampaignORM | None] = relationship(back_populates="sites")


class CertificateORM(Base):
    """Tabela ``certificates`` — certificados SSL/TLS observados."""

    __tablename__ = "certificates"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    serial_number: Mapped[str] = mapped_column(String(128), index=True, default="")
    issuer: Mapped[str] = mapped_column(String(512), default="")
    subject: Mapped[str] = mapped_column(String(512), default="")
    fingerprint: Mapped[str] = mapped_column(String(128), index=True, default="")
    not_before: Mapped[str] = mapped_column(String(64), default="")
    not_after: Mapped[str] = mapped_column(String(64), default="")
    pem: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)

    __table_args__ = (
        # Um certificado é único pela combinação serial + fingerprint.
        UniqueConstraint("serial_number", "fingerprint", name="uq_cert_serial_fp"),
    )


class InfrastructureORM(Base):
    """Tabela ``infrastructures`` — metadados de hospedagem (IP/ASN)."""

    __tablename__ = "infrastructures"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ip: Mapped[str] = mapped_column(String(64), index=True, default="")
    asn: Mapped[str] = mapped_column(String(32), index=True, default="")
    provider: Mapped[str] = mapped_column(String(255), default="")
    organization: Mapped[str] = mapped_column(String(255), default="")
    country: Mapped[str] = mapped_column(String(8), default="")
    domain: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class FingerprintORM(Base):
    """Tabela ``fingerprints`` — hashes estruturais para correlação."""

    __tablename__ = "fingerprints"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    dom_hash: Mapped[str] = mapped_column(String(64), index=True, default="")
    asset_hash: Mapped[str] = mapped_column(String(64), index=True, default="")
    script_hash: Mapped[str] = mapped_column(String(64), index=True, default="")
    campaign_fingerprint: Mapped[str] = mapped_column(
        String(64), index=True, default=""
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class MispEventORM(Base):
    """Tabela ``misp_events`` — vínculo com eventos criados no MISP."""

    __tablename__ = "misp_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_uuid: Mapped[str] = mapped_column(String(64), index=True, default="")
    event_id: Mapped[str] = mapped_column(String(32), default="")
    campaign_fingerprint: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
