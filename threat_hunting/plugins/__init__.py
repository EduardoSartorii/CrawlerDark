"""
Plugin System
=============

The plugin system allows extending the platform without modifying core code:
    - Custom connectors
    - Custom detection rules
    - Custom exporters
    - Custom enrichers

Plugin discovery happens via:
    1. Filesystem scanning (the connectors/ directory)
    2. Python entry points (installed packages)
    3. Manual registration via the PluginLoader

See threat_hunting/infrastructure/connectors/registry.py for connector
auto-discovery details.
"""

from threat_hunting.plugins.loader import PluginLoader

__all__ = ["PluginLoader"]
