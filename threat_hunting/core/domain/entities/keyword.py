"""
Keyword & Watchlist Entities.

Defines the intelligence requirements — what the platform is looking for.
These entities drive the Detection Engine: every collected item is matched
against active watchlists and keywords.

Business Rules:
    - Keywords have a type (regex, exact, fuzzy) and a weight (scoring boost)
    - Watchlists group keywords by purpose (brand, VIP, IOC, etc.)
    - Keywords can be globally enabled/disabled without deletion
    - VIP and brand keywords carry higher default weights
    - Keywords are never hardcoded — all loaded dynamically from storage
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import Field, field_validator

from .base import BaseEntity


class KeywordType(StrEnum):
    """Detection matching strategy for a keyword."""

    EXACT = "exact"
    REGEX = "regex"
    FUZZY = "fuzzy"
    GLOB = "glob"
    YARA = "yara"
    SIGMA = "sigma"


class KeywordCategory(StrEnum):
    """Business domain the keyword belongs to."""

    BRAND = "brand"
    VIP = "vip"
    EXECUTIVE = "executive"
    DOMAIN = "domain"
    EMAIL = "email"
    CPF = "cpf"
    CNPJ = "cnpj"
    CREDIT_CARD = "credit_card"
    WALLET = "wallet"
    IOC = "ioc"
    THREAT_ACTOR = "threat_actor"
    MALWARE = "malware"
    CAMPAIGN = "campaign"
    CREDENTIAL = "credential"
    GITHUB = "github"
    TELEGRAM = "telegram"
    CUSTOM = "custom"


class Keyword(BaseEntity):
    """
    A single intelligence requirement entry.

    The Detection Engine evaluates every Finding's content against
    all active keywords. Matches boost the Finding's score.
    """

    value: str = Field(..., min_length=1, description="Keyword value or pattern")
    keyword_type: KeywordType = Field(default=KeywordType.EXACT)
    category: KeywordCategory = Field(default=KeywordCategory.CUSTOM)
    weight: float = Field(default=1.0, ge=0.0, le=10.0, description="Score boost weight")
    is_active: bool = Field(default=True)
    case_sensitive: bool = Field(default=False)
    description: str = Field(default="")
    watchlist_id: str | None = Field(default=None)
    owner: str = Field(default="", description="Owning organization or analyst")
    context: str = Field(default="", description="Why this keyword is tracked")

    @field_validator("value")
    @classmethod
    def strip_value(cls, v: str) -> str:
        return v.strip()

    def enable(self) -> None:
        self.is_active = True
        self.touch()

    def disable(self) -> None:
        self.is_active = False
        self.touch()


class Watchlist(BaseEntity):
    """
    A named collection of keywords forming an intelligence requirement.

    Examples:
        - "Acme Corp Brand Monitoring"
        - "VIP Executives Q4 2024"
        - "Ransomware IOC Feed"

    The watchlist owns its keywords but also delegates to the Keyword entity
    for individual management.
    """

    name: str = Field(..., min_length=1)
    description: str = Field(default="")
    is_active: bool = Field(default=True)
    category: str = Field(default="general")
    owner: str = Field(default="")
    tags: list[str] = Field(default_factory=list)
    keyword_ids: list[str] = Field(default_factory=list)
    notify_on_match: bool = Field(default=True)
    auto_export: bool = Field(default=False)
    min_score_threshold: float = Field(default=5.0, ge=0.0, le=10.0)

    def add_keyword_id(self, keyword_id: str) -> None:
        if keyword_id not in self.keyword_ids:
            self.keyword_ids.append(keyword_id)
            self.touch()

    def remove_keyword_id(self, keyword_id: str) -> None:
        if keyword_id in self.keyword_ids:
            self.keyword_ids.remove(keyword_id)
            self.touch()

    @property
    def keyword_count(self) -> int:
        return len(self.keyword_ids)
