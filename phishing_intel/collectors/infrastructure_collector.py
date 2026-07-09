"""Coletor de metadados de infraestrutura (IP/ASN/hosting).

Arquitetura
-----------
Dado um domínio ou IP, resolve o IP (se necessário) e consulta dados de RDAP
via ``ipwhois`` para obter ASN, organização, provedor de hospedagem e país.
A estrutura de saída é preparada para futuras integrações com Passive DNS,
SecurityTrails, RiskIQ, WhoisXML, Shodan e CIRCL.

Responsabilidade do componente
------------------------------
Enriquecer a análise com contexto de rede, de forma resiliente (falhas de
rede resultam em objeto parcial, nunca em crash).

Fluxo de execução
-----------------
``collect(domain)`` -> resolve IP -> RDAP lookup -> :class:`InfrastructureInfo`.
"""

from __future__ import annotations

import socket

from phishing_intel.logging_config import get_logger
from phishing_intel.models.infrastructure import InfrastructureInfo

logger = get_logger(__name__)


class InfrastructureCollector:
    """Extrai metadados de infraestrutura de domínios/IPs."""

    def __init__(self) -> None:
        """Inicializa o coletor."""
        # Sem estado de rede persistente; cada lookup é independente.

    def resolve_ip(self, domain: str) -> str:
        """Resolve o primeiro IP de um domínio.

        Args:
            domain: Domínio a resolver.

        Returns:
            Endereço IP como string, ou string vazia em caso de falha.
        """
        try:
            return socket.gethostbyname(domain)
        except OSError:
            return ""

    def collect(self, domain: str = "", ip: str = "") -> InfrastructureInfo:
        """Coleta metadados de infraestrutura para um domínio ou IP.

        Args:
            domain: Domínio alvo (opcional se ``ip`` for informado).
            ip: IP alvo (opcional se ``domain`` for informado).

        Returns:
            :class:`InfrastructureInfo` com os dados disponíveis. Campos não
            resolvidos permanecem vazios.
        """
        info = InfrastructureInfo(domain=domain, ip=ip)

        # Resolve o IP a partir do domínio quando não fornecido.
        if not info.ip and domain:
            info.ip = self.resolve_ip(domain)

        if not info.ip:
            logger.warning("infra_no_ip", domain=domain)
            return info

        self._rdap_lookup(info)
        return info

    def _rdap_lookup(self, info: InfrastructureInfo) -> None:
        """Preenche ``info`` com dados de RDAP (ASN/org/país) via ipwhois.

        A importação de ``ipwhois`` é feita localmente para que o pacote
        funcione mesmo em ambientes onde a dependência não esteja instalada
        (degradação graciosa).

        Args:
            info: Objeto a ser preenchido in-place.
        """
        try:
            from ipwhois import IPWhois  # import local (degradação graciosa)

            obj = IPWhois(info.ip)
            result = obj.lookup_rdap(depth=1)

            info.asn = f"AS{result.get('asn', '')}".replace("ASNone", "").strip()
            info.country = result.get("asn_country_code", "") or ""
            info.organization = result.get("asn_description", "") or ""

            # O provedor de hospedagem costuma vir do nome da entidade de rede.
            network = result.get("network", {}) or {}
            info.hosting_provider = network.get("name", "") or info.organization

            info.enrichment_sources.append("ipwhois_rdap")
            info.raw = {"asn_cidr": result.get("asn_cidr", "")}
            logger.info(
                "infra_collected",
                ip=info.ip,
                asn=info.asn,
                provider=info.hosting_provider,
            )
        except Exception as exc:
            # Sem rede / dependência ausente / IP privado → seguimos parcial.
            logger.warning("infra_rdap_failed", ip=info.ip, error=str(exc))
