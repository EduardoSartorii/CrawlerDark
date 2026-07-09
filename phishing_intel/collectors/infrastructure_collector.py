"""Coletor de infraestrutura de rede.

Responsabilidade do componente
-------------------------------
Combinar a resolucao DNS (``dns_collector``) com consultas WHOIS/RDAP via
``ipwhois`` para produzir um :class:`~models.findings.InfrastructureFinding`
completo (IP, ASN, organizacao do ASN, provedor de hospedagem e pais).

Fluxo de execucao
------------------
1. Resolve o dominio para obter o(s) IP(s) associados (``dns_collector``).
2. Executa lookup RDAP/WHOIS do primeiro IP resolvido via ``IPWhois``.
3. Normaliza o resultado em ``InfrastructureFinding``, ja estruturado para
   futura correlacao cruzada com Passive DNS, SecurityTrails, RiskIQ,
   WhoisXML, Shodan e CIRCL (ver ``models/infrastructure.py``).
"""

from __future__ import annotations

import logging

from ipwhois import IPWhois
from ipwhois.exceptions import IPDefinedError

from collectors.dns_collector import resolve_domain
from models.findings import InfrastructureFinding

logger = logging.getLogger(__name__)


class InfrastructureCollectionError(RuntimeError):
    """Levantado quando nao e possivel determinar a infraestrutura de um dominio."""


def collect_infrastructure(domain: str) -> InfrastructureFinding:
    """Coleta os dados de infraestrutura de rede associados a um dominio.

    Args:
        domain: Dominio suspeito (sem protocolo/path).

    Returns:
        :class:`InfrastructureFinding` com os dados disponiveis. Campos que
        nao puderem ser determinados permanecem ``None`` (design tolerante
        a falhas parciais, pois a analise de conteudo nao deve ser
        bloqueada por indisponibilidade de enriquecimento de rede).
    """
    dns_result = resolve_domain(domain)
    ip_candidates = dns_result.a_records or dns_result.aaaa_records
    if not ip_candidates:
        logger.warning("Nenhum IP resolvido para %s; infraestrutura incompleta", domain)
        return InfrastructureFinding(domain=domain)

    primary_ip = ip_candidates[0]
    try:
        return _lookup_ip_whois(domain, primary_ip)
    except IPDefinedError as exc:
        logger.info("IP %s e reservado/privado, sem dados WHOIS publicos: %s", primary_ip, exc)
        return InfrastructureFinding(domain=domain, ip=primary_ip)
    except Exception as exc:  # noqa: BLE001 - coleta best-effort, nunca deve propagar
        logger.error("Falha no lookup WHOIS/RDAP de %s: %s", primary_ip, exc)
        return InfrastructureFinding(domain=domain, ip=primary_ip)


def _lookup_ip_whois(domain: str, ip: str) -> InfrastructureFinding:
    """Executa o lookup RDAP e normaliza a organizacao/pais/ASN do resultado."""
    whois_client = IPWhois(ip)
    rdap_result = whois_client.lookup_rdap(depth=1)

    network = rdap_result.get("network") or {}
    asn = rdap_result.get("asn")
    asn_description = rdap_result.get("asn_description")

    return InfrastructureFinding(
        domain=domain,
        ip=ip,
        asn=f"AS{asn}" if asn else None,
        asn_organization=asn_description,
        hosting_provider=network.get("name") or asn_description,
        country=rdap_result.get("asn_country_code") or network.get("country"),
    )
