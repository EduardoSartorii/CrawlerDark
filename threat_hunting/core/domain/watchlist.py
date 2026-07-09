"""Hunting targets: keywords, watchlists, VIPs, brands, actors, campaigns.

Responsibility
--------------
Model *what* the platform is hunting for. These entities drive the detection
and scoring engines and are the objects a future Django admin will manage.

Business rules
--------------
* A ``Keyword`` may be a plain term or a regular expression; the detection
  engine decides how to match based on ``is_regex``.
* A ``Watchlist`` groups keywords and target entities under a monitoring
  category (e.g. VIP monitoring, brand monitoring), and carries a base weight
  used by the scoring engine.
"""

from __future__ import annotations

import uuid
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from threat_hunting.core.domain.enums import Category


def _new_id() -> str:
    return uuid.uuid4().hex


class _Target(BaseModel):
    """Base for hunting targets (validate on assignment, forbid typos)."""

    model_config = ConfigDict(validate_assignment=True, extra="forbid")

    id: str = Field(default_factory=_new_id)
    enabled: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)


class Keyword(_Target):
    """A single term or regular expression to hunt for."""

    term: str
    is_regex: bool = False
    case_sensitive: bool = False
    weight: float = 10.0
    tags: list[str] = Field(default_factory=list)


class VIP(_Target):
    """A monitored person (executive, public figure)."""

    name: str
    aliases: list[str] = Field(default_factory=list)
    emails: list[str] = Field(default_factory=list)
    role: str | None = None
    organization: str | None = None
    weight: float = 25.0


class Brand(_Target):
    """A monitored brand/product and its digital footprint."""

    name: str
    domains: list[str] = Field(default_factory=list)
    keywords: list[str] = Field(default_factory=list)
    weight: float = 20.0


class ThreatActor(_Target):
    """A tracked adversary."""

    name: str
    aliases: list[str] = Field(default_factory=list)
    motivations: list[str] = Field(default_factory=list)
    ttps: list[str] = Field(default_factory=list)
    weight: float = 30.0


class Campaign(_Target):
    """A tracked malicious campaign."""

    name: str
    aliases: list[str] = Field(default_factory=list)
    actors: list[str] = Field(default_factory=list)
    weight: float = 25.0


class Watchlist(_Target):
    """A named collection of hunting targets under a monitoring category."""

    name: str
    category: Category = Category.THREAT_HUNTING
    keywords: list[Keyword] = Field(default_factory=list)
    vips: list[VIP] = Field(default_factory=list)
    brands: list[Brand] = Field(default_factory=list)
    actors: list[ThreatActor] = Field(default_factory=list)
    campaigns: list[Campaign] = Field(default_factory=list)
    base_weight: float = 1.0

    def active_keywords(self) -> list[Keyword]:
        """Return only enabled keywords (respecting the watchlist toggle)."""
        if not self.enabled:
            return []
        return [k for k in self.keywords if k.enabled]
