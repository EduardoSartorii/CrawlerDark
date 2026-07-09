"""Enrichment engines plugáveis (whois, geoip, threatfox, ...).

Aqui fornecemos ``NoopEnrichmentEngine`` (default sem custo) e
``CompositeEnrichmentEngine`` para agregar provedores externos. Cada provider
concreto (ex.: WhoisEnricher) pode ser adicionado sem alterar o core.
"""

from .composite_enrichment_engine import CompositeEnrichmentEngine
from .noop_enrichment_engine import NoopEnrichmentEngine

__all__ = ["CompositeEnrichmentEngine", "NoopEnrichmentEngine"]
