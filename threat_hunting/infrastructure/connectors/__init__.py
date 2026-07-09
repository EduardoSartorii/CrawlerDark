"""
Connector package.

All connectors are auto-discovered by the plugin registry.
Simply importing this package is sufficient for discovery.
"""

from .base import BaseConnector, CollectionContext, ConnectorHealth, ConnectorStatus
from .alienvault_connector import AlienVaultOTXConnector
from .github_connector import GitHubConnector
from .paste_connector import PasteSiteConnector
from .reddit_connector import RedditConnector
from .rss_connector import RSSConnector
from .threatfox_connector import ThreatFoxConnector

__all__ = [
    "BaseConnector",
    "CollectionContext",
    "ConnectorHealth",
    "ConnectorStatus",
    "RedditConnector",
    "GitHubConnector",
    "ThreatFoxConnector",
    "AlienVaultOTXConnector",
    "PasteSiteConnector",
    "RSSConnector",
]
