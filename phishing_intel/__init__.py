"""phishing_intel — Plataforma profissional de Cyber Threat Intelligence.

Este pacote fornece um pipeline completo para análise, classificação,
correlação, enriquecimento e atribuição de campanhas de phishing recebidas
de parceiros de CTI.

Arquitetura (visão geral):

* ``collectors``   — obtenção de artefatos (HTML, SSL, DNS, infraestrutura).
* ``analyzers``    — análise estática de HTML/JS, classificação e fingerprint.
* ``correlators``  — motor de correlação de campanhas e cálculo de atribuição.
* ``enrichment``   — integração com o MISP, taxonomias e construção de campanhas.
* ``database``     — camada de persistência (SQLAlchemy + repositórios).
* ``models``       — modelos de domínio (Pydantic) trafegados no pipeline.
* ``config``       — carregamento de configuração declarativa (YAML).

O ponto de entrada de orquestração é :mod:`phishing_intel.main`.
"""

from __future__ import annotations

__version__ = "1.0.0"

__all__ = ["__version__"]
