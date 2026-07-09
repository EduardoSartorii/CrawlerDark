"""Configuration layer.

Exposes the strongly-typed :class:`~phishing_intel.config.settings.Settings`
model and the :func:`~phishing_intel.config.settings.load_settings` helper used
across the platform to obtain validated runtime configuration.
"""

from phishing_intel.config.settings import (
    AppSettings,
    CorrelationSettings,
    DatabaseSettings,
    LoggingSettings,
    MISPSettings,
    Settings,
    load_settings,
)

__all__ = [
    "AppSettings",
    "CorrelationSettings",
    "DatabaseSettings",
    "LoggingSettings",
    "MISPSettings",
    "Settings",
    "load_settings",
]
