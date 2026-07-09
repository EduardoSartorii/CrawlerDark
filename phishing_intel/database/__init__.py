"""Persistence layer (SQLAlchemy).

Re-exports the ORM base/models, the :class:`Database` session manager and the
repository classes for ergonomic imports.
"""

from phishing_intel.database.models import (
    Base,
    Campaign,
    Certificate,
    Fingerprint,
    Infrastructure,
    MispEvent,
    PhishingSite,
)
from phishing_intel.database.repositories import (
    AnalysisRepository,
    CampaignRepository,
    MispEventRepository,
    SiteRepository,
)
from phishing_intel.database.session import Database, get_db, init_db

__all__ = [
    "AnalysisRepository",
    "Base",
    "Campaign",
    "CampaignRepository",
    "Certificate",
    "Database",
    "Fingerprint",
    "Infrastructure",
    "MispEvent",
    "MispEventRepository",
    "PhishingSite",
    "SiteRepository",
    "get_db",
    "init_db",
]
