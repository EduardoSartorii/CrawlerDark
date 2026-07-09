"""Subpacote de enriquecimento (MISP e taxonomias).

Responsabilidade
----------------
Traduzir os resultados da análise/correlação em eventos, objetos, atributos
e tags do MISP. Inclui o mapeador de taxonomias/tags locais e o construtor
de eventos de campanha.

Componentes
-----------
* ``misp_client``     — cliente PyMISP (criação de eventos/objetos/atributos).
* ``taxonomy_mapper`` — geração das tags locais ``fraude:*``.
* ``campaign_builder``— monta o payload de evento a partir da campanha.
"""

from __future__ import annotations

from phishing_intel.enrichment.campaign_builder import CampaignBuilder, MispEventPayload
from phishing_intel.enrichment.misp_client import MispClient
from phishing_intel.enrichment.taxonomy_mapper import TaxonomyMapper

__all__ = [
    "CampaignBuilder",
    "MispClient",
    "MispEventPayload",
    "TaxonomyMapper",
]
