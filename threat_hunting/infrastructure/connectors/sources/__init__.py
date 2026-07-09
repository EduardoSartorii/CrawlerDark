"""Concrete connector implementations (auto-discovered by the registry).

Each module here defines one or more :class:`BaseConnector` subclasses with a
class-level ``meta``. Dropping a new module in this package is enough for the
platform to pick up a new source — nothing else needs editing.

The set below is representative (social, code, feeds, dark web, news, paste).
The remaining requested sources (Facebook, Instagram, X, Discord, GitLab,
OpenCTI, GreyNoise, VirusTotal, AbuseIPDB, Shodan, Censys, URLHaus, OTX, ...)
follow the exact same shape and are added the same way.
"""
