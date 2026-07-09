"""Modelos de campanha, fingerprint e atribuição.

Arquitetura
-----------
Define o "bundle" de fingerprints de um site, os sinais de correlação e o
objeto :class:`Campaign` que representa uma campanha atribuída com seu score
de confiança.

Responsabilidade do componente
------------------------------
Fornecer as estruturas usadas pelo motor de correlação para agrupar sites
em campanhas e calcular o Attribution Score.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field


class ConfidenceLevel(str, Enum):
    """Nível de confiança da atribuição, derivado do score numérico.

    Regras de negócio (limiares padrão):
        * 0-39   -> ``LOW``
        * 40-69  -> ``MEDIUM``
        * 70-100 -> ``HIGH``
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class FingerprintBundle(BaseModel):
    """Conjunto de hashes que identificam a "cara" técnica de um site.

    O ``campaign_fingerprint`` é um hash composto (DOM + assets + scripts +
    estrutura de diretórios) usado para correlacionar campanhas futuras.
    """

    dom_hash: str = ""
    asset_hash: str = ""
    script_hash: str = ""
    # Fingerprint composto (correlaciona campanhas ao longo do tempo).
    campaign_fingerprint: str = ""
    # Caminhos/diretórios normalizados usados na composição do fingerprint.
    directory_structure: list[str] = Field(default_factory=list)


class AttributionSignal(BaseModel):
    """Um sinal individual que contribuiu para o Attribution Score.

    Attributes:
        name: Nome do sinal (ex.: ``fingerprint``, ``certificate``).
        matched: Se o sinal bateu com a campanha candidata.
        weight: Peso configurado do sinal.
        detail: Descrição legível do que casou (para auditoria).
    """

    name: str
    matched: bool
    weight: float
    detail: str = ""


class Campaign(BaseModel):
    """Uma campanha de phishing correlacionada e atribuída.

    Attributes:
        campaign_id: Identificador estável da campanha (derivado do
            fingerprint composto).
        score: Attribution Score 0-100.
        confidence: Nível de confiança derivado do score.
        signals: Sinais que embasaram a atribuição.
        target_brand: Marca-alvo predominante da campanha.
        phishing_type: Objetivo predominante da campanha.
        site_urls: URLs dos sites vinculados à campanha.
    """

    campaign_id: str
    score: int = 0
    confidence: ConfidenceLevel = ConfidenceLevel.LOW
    signals: list[AttributionSignal] = Field(default_factory=list)
    target_brand: str = ""
    phishing_type: str = ""
    hosting_provider: str = ""
    asn: str = ""
    kit_fingerprint: str = ""
    ssl_fingerprint: str = ""
    ssl_serial: str = ""
    site_urls: list[str] = Field(default_factory=list)
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
