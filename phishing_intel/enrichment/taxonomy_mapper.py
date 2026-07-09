"""Mapeador de taxonomias e tags locais (taxonomy_mapper).

Responsabilidade do componente
-------------------------------
Traduzir o resultado consolidado da analise/correlacao de um incidente
(marca-alvo, tipo de phishing, campanha, infraestrutura, canais de
exfiltracao) em tags locais no formato ``fraude:<namespace>=<valor>``,
prontas para serem anexadas a eventos MISP pelo ``misp_client``.

Namespaces suportados
----------------------
* ``fraude:marca``          -> marca-alvo identificada (ex.: ``livelo``).
* ``fraude:objetivo``       -> tipo de phishing (ex.: ``account_takeover``).
* ``fraude:campanha``       -> identificador da campanha correlacionada.
* ``fraude:infraestrutura`` -> ASN ou provedor de hospedagem.
* ``fraude:criticidade``    -> nivel de criticidade derivado do tipo de
  phishing e da confianca de atribuicao.
* ``fraude:exfiltracao``    -> canal(is) de exfiltracao identificados.

Regra de negocio
----------------
A criticidade e elevada para "alta" sempre que o tipo de phishing for OTP
Harvesting ou Card Harvesting, independentemente do Attribution Score,
pois estes objetivos permitem fraude financeira imediata mesmo em
incidentes isolados (sem correlacao historica).
"""

from __future__ import annotations

import unicodedata

from models.campaign import AttributionScore, Campaign, ConfidenceLevel
from models.findings import AnalysisReport, PhishingType

_HIGH_CRITICALITY_TYPES = {PhishingType.OTP_HARVESTING, PhishingType.CARD_HARVESTING}
_MEDIUM_CRITICALITY_TYPES = {PhishingType.ACCOUNT_TAKEOVER, PhishingType.IDENTITY_THEFT}


def _slugify(value: str) -> str:
    """Normaliza um valor textual para uso seguro como sufixo de tag MISP."""
    normalized = unicodedata.normalize("NFKD", value)
    ascii_only = "".join(char for char in normalized if not unicodedata.combining(char))
    return ascii_only.strip().lower().replace(" ", "_")


def derive_criticality(report: AnalysisReport, attribution: AttributionScore) -> str:
    """Deriva o nivel de criticidade textual (``baixa``/``media``/``alta``) do incidente.

    Args:
        report: Relatorio de analise agregado do incidente.
        attribution: Score de atribuicao calculado pelo motor de correlacao.

    Returns:
        Um entre ``"baixa"``, ``"media"`` ou ``"alta"``.
    """
    if report.classification.phishing_type in _HIGH_CRITICALITY_TYPES:
        return "alta"
    if attribution.confidence == ConfidenceLevel.HIGH:
        return "alta"
    if report.classification.phishing_type in _MEDIUM_CRITICALITY_TYPES:
        return "media"
    if attribution.confidence == ConfidenceLevel.MEDIUM:
        return "media"
    return "baixa"


def build_tags(report: AnalysisReport, campaign: Campaign, attribution: AttributionScore) -> list[str]:
    """Constroi a lista completa de tags locais ``fraude:*`` para um incidente.

    Args:
        report: Relatorio de analise agregado do incidente.
        campaign: Campanha (nova ou existente) a qual o incidente foi
            associado pelo motor de correlacao.
        attribution: Score de atribuicao calculado.

    Returns:
        Lista de strings de tag, sem duplicatas, prontas para uso no MISP.
    """
    tags: list[str] = []

    if report.brand.target_brand:
        tags.append(f"fraude:marca={_slugify(report.brand.target_brand)}")

    if report.classification.phishing_type != PhishingType.UNKNOWN:
        tags.append(f"fraude:objetivo={report.classification.phishing_type.value}")

    if campaign.campaign_id:
        tags.append(f"fraude:campanha={_slugify(campaign.campaign_id)}")

    if report.infrastructure and (report.infrastructure.asn or report.infrastructure.hosting_provider):
        infra_value = report.infrastructure.asn or report.infrastructure.hosting_provider or ""
        tags.append(f"fraude:infraestrutura={_slugify(infra_value)}")

    tags.append(f"fraude:criticidade={derive_criticality(report, attribution)}")

    for destination in report.exfiltration.destinations:
        tags.append(f"fraude:exfiltracao={destination.channel.value}")

    # Remove duplicatas preservando a ordem de insercao original.
    return list(dict.fromkeys(tags))
