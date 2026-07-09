"""Modelos de dominio de campanhas e atribuicao.

Responsabilidade do componente
-------------------------------
Definir os contratos usados pelo motor de correlacao (``correlators/*``)
para expressar sinais de correlacao entre incidentes, o score de atribuicao
resultante e a entidade "Campanha" final, que agrupa multiplos incidentes
(``phishing_sites``) sob uma mesma identidade de ameaca.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field


class ConfidenceLevel(str, Enum):
    """Faixa de confianca do Attribution Score.

    Regra de negocio (definida no briefing operacional):
        * 0-39   -> baixa confianca
        * 40-69  -> media confianca
        * 70-100 -> alta confianca
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @classmethod
    def from_score(cls, score: float, medium_max: int = 69, low_max: int = 39) -> "ConfidenceLevel":
        """Deriva o nivel de confianca a partir de um score numerico (0-100)."""
        if score <= low_max:
            return cls.LOW
        if score <= medium_max:
            return cls.MEDIUM
        return cls.HIGH


class CorrelationSignalType(str, Enum):
    """Tipos de sinais utilizados pelo motor de correlacao de campanhas."""

    SAME_FINGERPRINT = "same_fingerprint"
    SAME_CERTIFICATE = "same_certificate"
    SAME_ASN = "same_asn"
    SAME_HOSTING_PROVIDER = "same_hosting_provider"
    SAME_DOM_PATTERN = "same_dom_pattern"
    SAME_JAVASCRIPT_PATTERN = "same_javascript_pattern"
    SAME_TARGET_BRAND = "same_target_brand"


class CorrelationSignal(BaseModel):
    """Um sinal individual de correlacao entre dois incidentes/sites."""

    signal_type: CorrelationSignalType
    weight: int
    matched_value: str
    related_site_url: str | None = None


class AttributionScore(BaseModel):
    """Resultado do calculo de atribuicao entre um novo achado e o historico.

    ``score`` e a soma (limitada a 100) dos pesos de todos os sinais que
    bateram positivamente contra incidentes previamente conhecidos.
    """

    score: float = Field(ge=0.0, le=100.0)
    confidence: ConfidenceLevel
    signals: list[CorrelationSignal] = Field(default_factory=list)
    correlated_site_urls: list[str] = Field(default_factory=list)


class Campaign(BaseModel):
    """Entidade "Campanha": agrupamento de incidentes correlacionados.

    Uma campanha e criada/atualizada sempre que um novo incidente atinge
    confianca >= media com um cluster existente, ou criada do zero quando
    nenhuma correlacao suficiente e encontrada (campanha "orfa" ate que
    futuros incidentes a conectem a outras).
    """

    campaign_id: str
    score: float = Field(ge=0.0, le=100.0)
    confidence: ConfidenceLevel
    target_brand: str | None = None
    phishing_type: str | None = None
    kit_fingerprint: str | None = None
    member_site_urls: list[str] = Field(default_factory=list)
    misp_event_uuid: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
