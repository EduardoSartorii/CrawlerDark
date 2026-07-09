"""Category — classificação primária de um ``Finding``."""

from __future__ import annotations

from enum import Enum


class Category(str, Enum):
    """Categorias suportadas pela plataforma."""

    LEAK = "LEAK"
    CREDENTIAL = "CREDENTIAL"
    CARD = "CARD"
    DOCUMENT = "DOCUMENT"
    MALWARE = "MALWARE"
    BRAND = "BRAND"
    VIP = "VIP"
    IOC = "IOC"
    RANSOMWARE = "RANSOMWARE"
    PHISHING = "PHISHING"
    DARKWEB = "DARKWEB"
    SOCIAL = "SOCIAL"
    NEWS = "NEWS"
    CAMPAIGN = "CAMPAIGN"
    THREAT_ACTOR = "THREAT_ACTOR"
    OTHER = "OTHER"

    @classmethod
    def coerce(cls, value: str | "Category") -> "Category":
        """Constrói a partir de string case-insensitive, com fallback OTHER."""
        if isinstance(value, cls):
            return value
        try:
            return cls[value.strip().upper()]
        except KeyError:
            return cls.OTHER
