"""Coletor de registros DNS.

Arquitetura
-----------
Resolve os registros DNS relevantes de um domínio (A, AAAA, MX, NS, TXT,
CNAME) usando ``dnspython``. Os resultados alimentam a correlação de
infraestrutura e o enriquecimento MISP.

Responsabilidade do componente
------------------------------
Fornecer uma visão consolidada de DNS de forma resiliente — timeouts e
domínios inexistentes resultam em listas vazias, nunca em exceção.

Fluxo de execução
-----------------
``resolve(domain)`` -> consulta cada tipo de registro -> :class:`DnsRecords`.
"""

from __future__ import annotations

import dns.resolver

from phishing_intel.logging_config import get_logger
from phishing_intel.models.infrastructure import DnsRecords

logger = get_logger(__name__)

# Tipos de registro consultados e o atributo de destino em DnsRecords.
_RECORD_TYPES: tuple[str, ...] = ("A", "AAAA", "MX", "NS", "TXT", "CNAME")


class DnsCollector:
    """Resolve registros DNS de domínios suspeitos."""

    def __init__(self, timeout: float = 5.0) -> None:
        """Inicializa o coletor com um resolver configurado.

        Args:
            timeout: Timeout por consulta (segundos).
        """
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

    def _query(self, domain: str, record_type: str) -> list[str]:
        """Executa uma única consulta DNS de forma tolerante a falhas.

        Args:
            domain: Domínio alvo.
            record_type: Tipo de registro (ex.: ``A``, ``MX``).

        Returns:
            Lista de valores textuais; vazia se não houver resposta ou erro.
        """
        try:
            answers = self.resolver.resolve(domain, record_type)
            return [rdata.to_text().strip('"') for rdata in answers]
        except Exception:
            # NXDOMAIN, timeout, no-answer etc. são esperados — não é erro
            # de execução; retornamos vazio e seguimos.
            return []

    def resolve(self, domain: str) -> DnsRecords:
        """Resolve todos os tipos de registro relevantes para um domínio.

        Args:
            domain: Domínio a resolver.

        Returns:
            :class:`DnsRecords` com os registros encontrados.
        """
        records = DnsRecords(domain=domain)
        if not domain:
            return records

        records.a = self._query(domain, "A")
        records.aaaa = self._query(domain, "AAAA")
        records.mx = self._query(domain, "MX")
        records.ns = self._query(domain, "NS")
        records.txt = self._query(domain, "TXT")
        records.cname = self._query(domain, "CNAME")

        logger.info(
            "dns_resolved",
            domain=domain,
            a_count=len(records.a),
            mx_count=len(records.mx),
        )
        return records
