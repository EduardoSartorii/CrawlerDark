"""Coletor de dados DNS.

Responsabilidade do componente
-------------------------------
Resolver registros DNS (A, AAAA, NS, MX) de um dominio suspeito usando
``dnspython``, fornecendo os enderecos IP que alimentam o
``infrastructure_collector`` (lookup de ASN/organizacao/hosting provider).

Fluxo de execucao
------------------
1. Resolve registros ``A``/``AAAA`` para obter IPs.
2. Resolve registros ``NS``/``MX`` de forma best-effort (usados apenas como
   contexto adicional; falhas nestes registros nao interrompem a coleta).
"""

from __future__ import annotations

import logging

import dns.exception
import dns.resolver
from pydantic import BaseModel

logger = logging.getLogger(__name__)


class DnsResolutionResult(BaseModel):
    """Resultado consolidado da resolucao DNS de um dominio."""

    domain: str
    a_records: list[str] = []
    aaaa_records: list[str] = []
    ns_records: list[str] = []
    mx_records: list[str] = []


def _resolve_record_type(domain: str, record_type: str, timeout: float) -> list[str]:
    """Resolve um tipo de registro DNS especifico, tolerando ausencia do registro."""
    try:
        answer = dns.resolver.resolve(domain, record_type, lifetime=timeout)
        return [str(record).rstrip(".") for record in answer]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout) as exc:
        logger.debug("Sem registros %s para %s: %s", record_type, domain, exc)
        return []


def resolve_domain(domain: str, timeout: float = 5.0) -> DnsResolutionResult:
    """Resolve os principais registros DNS de um dominio suspeito.

    Args:
        domain: Dominio a ser resolvido (sem protocolo/path).
        timeout: Timeout por consulta, em segundos.

    Returns:
        :class:`DnsResolutionResult` com todos os registros encontrados.
    """
    return DnsResolutionResult(
        domain=domain,
        a_records=_resolve_record_type(domain, "A", timeout),
        aaaa_records=_resolve_record_type(domain, "AAAA", timeout),
        ns_records=_resolve_record_type(domain, "NS", timeout),
        mx_records=_resolve_record_type(domain, "MX", timeout),
    )
