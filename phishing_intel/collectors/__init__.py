"""Subpacote de coletores (fluxo secundário).

Responsabilidade
----------------
Obter artefatos quando eles *não* são fornecidos pelo parceiro de CTI:
HTML da página, certificado SSL, registros DNS e metadados de
infraestrutura. Segue o princípio de separação entre coleta e análise: os
coletores apenas obtêm e armazenam evidências; a análise ocorre depois.

Regra de negócio central
------------------------
A plataforma deve priorizar os artefatos recebidos e não depender da coleta
para funcionar. Todos os coletores são tolerantes a falha (retornam objetos
vazios/parciais em vez de derrubar o pipeline).
"""

from __future__ import annotations

from phishing_intel.collectors.dns_collector import DnsCollector
from phishing_intel.collectors.html_collector import HtmlCollector, RenderProfile
from phishing_intel.collectors.infrastructure_collector import (
    InfrastructureCollector,
)
from phishing_intel.collectors.ssl_collector import SslCollector

__all__ = [
    "DnsCollector",
    "HtmlCollector",
    "InfrastructureCollector",
    "RenderProfile",
    "SslCollector",
]
