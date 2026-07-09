"""Enrichment layer.

Maps analysis + attribution results into MISP events/objects/tags and builds
campaign domain objects. PyMISP is only imported when the MISP client is
actually used, keeping the rest of the platform free of that dependency at
import time.
"""

from phishing_intel.enrichment.campaign_builder import CampaignBuilder
from phishing_intel.enrichment.misp_client import MISPEnricher
from phishing_intel.enrichment.taxonomy_mapper import TaxonomyMapper

__all__ = [
    "CampaignBuilder",
    "MISPEnricher",
    "TaxonomyMapper",
]
