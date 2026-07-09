"""Mapeador de taxonomias e tags locais ``fraude:*``.

Arquitetura
-----------
Converte os resultados da análise/correlação nas tags locais exigidas pela
operação de CTI. As tags seguem o formato ``fraude:<eixo>=<valor>``.

Responsabilidade do componente
------------------------------
Centralizar as regras de negócio de tagging para que o :class:`MispClient`
apenas aplique as tags, sem lógica de mapeamento espalhada.

Eixos de taxonomia:
    * ``fraude:marca``         — marca-alvo (ex.: ``livelo``, ``itau``).
    * ``fraude:objetivo``      — objetivo (ex.: ``account_takeover``, ``otp``).
    * ``fraude:campanha``      — id da campanha correlacionada.
    * ``fraude:infraestrutura``— ASN/provedor.
    * ``fraude:criticidade``   — derivada da confiança de atribuição.
    * ``fraude:exfiltracao``   — canal de exfiltração (ex.: ``api``, ``email``).
"""

from __future__ import annotations

from phishing_intel.models.campaign import Campaign, ConfidenceLevel
from phishing_intel.models.findings import AnalysisResult

# Mapa de confiança de atribuição -> criticidade operacional.
_CRITICALITY_BY_CONFIDENCE = {
    ConfidenceLevel.HIGH: "alta",
    ConfidenceLevel.MEDIUM: "media",
    ConfidenceLevel.LOW: "baixa",
}


class TaxonomyMapper:
    """Gera as tags locais ``fraude:*`` para um evento MISP."""

    def build_tags(
        self, analysis: AnalysisResult, campaign: Campaign
    ) -> list[str]:
        """Constrói a lista de tags locais para a campanha/análise.

        Args:
            analysis: Resultado consolidado da análise.
            campaign: Campanha correlacionada e atribuída.

        Returns:
            Lista ordenada e deduplicada de tags no formato
            ``fraude:<eixo>=<valor>``.
        """
        tags: set[str] = set()

        # Eixo marca.
        if campaign.target_brand:
            tags.add(f'fraude:marca="{campaign.target_brand}"')

        # Eixo objetivo — uma tag por tipo de phishing detectado.
        for phishing_type in analysis.phishing_types:
            tags.add(f'fraude:objetivo="{phishing_type.value}"')

        # Eixo campanha.
        if campaign.campaign_id:
            tags.add(f'fraude:campanha="{campaign.campaign_id}"')

        # Eixo infraestrutura — ASN e/ou provedor.
        if campaign.asn:
            tags.add(f'fraude:infraestrutura="{campaign.asn}"')
        if campaign.hosting_provider:
            tags.add(f'fraude:infraestrutura="{campaign.hosting_provider}"')

        # Eixo criticidade — derivada da confiança de atribuição.
        criticality = _CRITICALITY_BY_CONFIDENCE.get(campaign.confidence, "baixa")
        tags.add(f'fraude:criticidade="{criticality}"')

        # Eixo exfiltração — um por canal distinto detectado.
        for dest in analysis.exfiltration:
            tags.add(f'fraude:exfiltracao="{dest.kind.value}"')

        return sorted(tags)
