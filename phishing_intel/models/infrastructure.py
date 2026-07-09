"""Modelos de dominio de infraestrutura e certificados.

Responsabilidade do componente
-------------------------------
Estruturar os dados de rede (dominio, IP, ASN, provedor de hospedagem, pais)
e de certificados X.509 em contratos reutilizaveis por coletores,
correlacionadores e pela camada de persistencia. Foi desenhado para ser
diretamente extensivel com integracoes futuras (Passive DNS, SecurityTrails,
RiskIQ, WhoisXML, Shodan, CIRCL) sem quebrar o restante da plataforma —
essas integracoes apenas populam mais campos do mesmo contrato.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class CertificateRecord(BaseModel):
    """Representacao normalizada e persistivel de um certificado X.509."""

    subject: str
    issuer: str
    serial_number: str
    san: list[str] = Field(default_factory=list)
    sha1_fingerprint: str
    sha256_fingerprint: str
    not_before: datetime
    not_after: datetime
    raw_pem: str | None = None


class InfrastructureRecord(BaseModel):
    """Representacao normalizada e persistivel de infraestrutura de rede.

    Regra de negocio: ``asn`` e ``hosting_provider`` sao os dois sinais mais
    fortes para o ``infrastructure_correlator`` reconhecer reuso de
    infraestrutura entre campanhas distintas (ex.: bulletproof hosting
    reutilizado por multiplos operadores).
    """

    domain: str | None = None
    ip: str | None = None
    asn: str | None = None
    asn_organization: str | None = None
    hosting_provider: str | None = None
    country: str | None = None
    passive_dns_records: list[str] = Field(default_factory=list)
    external_references: dict[str, str] = Field(default_factory=dict)
