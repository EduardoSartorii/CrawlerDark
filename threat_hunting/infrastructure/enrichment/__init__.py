"""Enrichment engine and providers.

Augments findings with external context per indicator. The
:class:`EnrichmentEngine` iterates registered
:class:`~threat_hunting.core.application.ports.enrichment.EnrichmentProvider`
strategies; each provider adds tags/metadata for the indicators it supports.
"""

from threat_hunting.infrastructure.enrichment.engine import EnrichmentEngine
from threat_hunting.infrastructure.enrichment.providers import (
    GeoTagProvider,
    DefangProvider,
)

__all__ = ["EnrichmentEngine", "GeoTagProvider", "DefangProvider"]
