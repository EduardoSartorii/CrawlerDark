"""Modelos de infraestrutura (SSL, DNS, hosting).

Arquitetura
-----------
Define estruturas tipadas para os artefatos de infraestrutura coletados:
certificado X.509, registros DNS e metadados de hospedagem (IP/ASN/provedor).

Responsabilidade do componente
------------------------------
Padronizar os dados de infraestrutura para persistência, correlação de
campanhas (mesmo ASN/certificado/provedor) e enriquecimento MISP.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class CertificateInfo(BaseModel):
    """Metadados normalizados de um certificado SSL/TLS (X.509)."""

    subject: str = ""
    issuer: str = ""
    serial_number: str = ""
    san: list[str] = Field(default_factory=list)
    sha1_fingerprint: str = ""
    sha256_fingerprint: str = ""
    not_before: str = ""
    not_after: str = ""
    # Certificado completo em PEM, preservado para cadeia de evidências.
    pem: str = ""


class DnsRecords(BaseModel):
    """Registros DNS resolvidos para um domínio."""

    domain: str = ""
    a: list[str] = Field(default_factory=list)
    aaaa: list[str] = Field(default_factory=list)
    mx: list[str] = Field(default_factory=list)
    ns: list[str] = Field(default_factory=list)
    txt: list[str] = Field(default_factory=list)
    cname: list[str] = Field(default_factory=list)


class InfrastructureInfo(BaseModel):
    """Metadados de infraestrutura/hospedagem de um IP ou domínio.

    A estrutura é propositalmente compatível com futuras integrações de
    Passive DNS, SecurityTrails, RiskIQ, WhoisXML, Shodan e CIRCL — os campos
    ``raw`` e ``enrichment_sources`` permitem anexar dados de terceiros.
    """

    domain: str = ""
    ip: str = ""
    asn: str = ""
    organization: str = ""
    hosting_provider: str = ""
    country: str = ""
    # Fontes de enriquecimento que já contribuíram (para rastreabilidade).
    enrichment_sources: list[str] = Field(default_factory=list)
    # Dados brutos de provedores externos (reservado para integrações).
    raw: dict = Field(default_factory=dict)
