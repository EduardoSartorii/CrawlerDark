"""Keyword & Watchlist entities.

Responsibility
--------------
Model the monitoring terms the platform hunts for: keywords, VIPs, brands,
domains, executives, threat actors, emails, CPF/CNPJ, cards, wallets, Telegram
handles, GitHub orgs, IOC lists, YARA/Sigma/Regex rules.

A :class:`Watchlist` is an aggregate of :class:`Keyword`s under a name. The
detection engine consumes watchlists to decide what to match. Because these are
data (loaded from config / future Django admin), no term is ever hardcoded.
"""

from __future__ import annotations

from enum import Enum
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator


class KeywordType(str, Enum):
    """Semantic type of a monitored term (drives which extractor/matcher runs)."""

    GENERIC = "generic"
    VIP = "vip"
    BRAND = "brand"
    COMPANY = "company"
    EXECUTIVE = "executive"
    DOMAIN = "domain"
    EMAIL = "email"
    CPF = "cpf"
    CNPJ = "cnpj"
    CARD_BIN = "card_bin"
    WALLET = "wallet"
    TELEGRAM = "telegram"
    GITHUB = "github"
    THREAT_ACTOR = "threat_actor"
    REGEX = "regex"
    YARA = "yara"
    SIGMA = "sigma"
    IOC = "ioc"


class Keyword(BaseModel):
    """A single monitored term with an optional weight and case sensitivity."""

    id: str = Field(default_factory=lambda: uuid4().hex)
    term: str = Field(min_length=1)
    type: KeywordType = KeywordType.GENERIC
    weight: float = Field(default=10.0, description="Score contribution when matched.")
    case_sensitive: bool = False
    enabled: bool = True

    @field_validator("term")
    @classmethod
    def _strip(cls, term: str) -> str:
        return term.strip()

    def matches(self, text: str) -> bool:
        """Return whether this keyword appears in ``text`` (respecting case flag)."""
        if not self.enabled:
            return False
        haystack = text if self.case_sensitive else text.lower()
        needle = self.term if self.case_sensitive else self.term.lower()
        return needle in haystack


class Watchlist(BaseModel):
    """A named collection of keywords the detection engine consumes."""

    id: str = Field(default_factory=lambda: uuid4().hex)
    name: str = Field(min_length=1)
    description: str = ""
    keywords: list[Keyword] = Field(default_factory=list)
    enabled: bool = True

    def enabled_keywords(self) -> list[Keyword]:
        """Return keywords that are active for matching."""
        if not self.enabled:
            return []
        return [kw for kw in self.keywords if kw.enabled]
