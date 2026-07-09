"""Correlation layer.

Compares a freshly analysed sample against the persisted historical record to
produce a weighted attribution score and link the sample to a campaign.
"""

from phishing_intel.correlators.campaign_correlator import CampaignCorrelator
from phishing_intel.correlators.fingerprint_correlator import FingerprintCorrelator
from phishing_intel.correlators.infrastructure_correlator import (
    InfrastructureCorrelator,
)

__all__ = [
    "CampaignCorrelator",
    "FingerprintCorrelator",
    "InfrastructureCorrelator",
]
