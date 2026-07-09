"""Correlacionador por infraestrutura de rede (infrastructure_correlator).

Responsabilidade do componente
-------------------------------
Comparar os dados de infraestrutura (ASN, provedor de hospedagem) de um
novo incidente contra o historico persistido, produzindo sinais de
correlacao para reuso de ASN (``same_asn``) e reuso de provedor de
hospedagem (``same_hosting_provider``).

Fluxo de execucao
------------------
1. Busca infraestruturas historicas com o mesmo ASN do incidente atual.
2. Busca infraestruturas historicas com o mesmo nome de provedor.
3. Resolve os sites associados a cada infraestrutura correlacionada via
   ``PhishingSiteRepository``.

Regra de negocio
----------------
ASN e um sinal de peso medio: operadores de phishing frequentemente usam
provedores "bulletproof" ou VPS descartaveis compartilhados por multiplas
campanhas nao necessariamente relacionadas, portanto este sinal, isolado,
NUNCA deve ser suficiente para atingir "alta confianca" no Attribution
Score — apenas combinado a outros sinais mais especificos.
"""

from __future__ import annotations

from database.repositories import InfrastructureRepository, PhishingSiteRepository
from models.campaign import CorrelationSignal, CorrelationSignalType
from models.findings import InfrastructureFinding


def correlate_by_infrastructure(
    infrastructure: InfrastructureFinding,
    infrastructure_repo: InfrastructureRepository,
    site_repo: PhishingSiteRepository,
) -> list[CorrelationSignal]:
    """Produz sinais de correlacao baseados em reuso de ASN/provedor de hospedagem.

    Args:
        infrastructure: Dados de infraestrutura do incidente atual.
        infrastructure_repo: Repositorio de infraestruturas persistidas.
        site_repo: Repositorio de sites de phishing.

    Returns:
        Lista de :class:`CorrelationSignal` (pode ser vazia).
    """
    signals: list[CorrelationSignal] = []

    if infrastructure.asn:
        for site in site_repo.find_by_infrastructure_asn(infrastructure.asn):
            signals.append(
                CorrelationSignal(
                    signal_type=CorrelationSignalType.SAME_ASN,
                    weight=0,
                    matched_value=infrastructure.asn,
                    related_site_url=site.url,
                )
            )

    if infrastructure.hosting_provider:
        for infra_match in infrastructure_repo.find_by_provider(infrastructure.hosting_provider):
            for site in site_repo.find_by_infrastructure_asn(infra_match.asn) if infra_match.asn else []:
                signals.append(
                    CorrelationSignal(
                        signal_type=CorrelationSignalType.SAME_HOSTING_PROVIDER,
                        weight=0,
                        matched_value=infrastructure.hosting_provider,
                        related_site_url=site.url,
                    )
                )

    return signals
