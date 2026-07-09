"""Domain rules for dynamic detection and configurable scoring."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class RuleType(StrEnum):
    """Supported dynamic detection rule types."""

    REGEX = "regex"
    YARA = "yara"
    SIGMA = "sigma"
    KEYWORD = "keyword"
    IOC_MATCH = "ioc_match"
    THREAT_ACTOR_MATCH = "threat_actor_match"
    HEURISTIC = "heuristic"
    WHITELIST = "whitelist"
    BLACKLIST = "blacklist"
    THRESHOLD = "threshold"
    COMPOSITE = "composite"


class DetectionRule(BaseModel):
    """Rule definition loaded from dynamic repository backends."""

    model_config = ConfigDict(extra="allow")

    rule_id: str
    name: str
    rule_type: RuleType
    expression: str
    enabled: bool = True
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ScoreWeights(BaseModel):
    """Weighted factors used by the scoring engine."""

    regex_match: float = 5.0
    yara_match: float = 5.0
    vip_match: float = 20.0
    ioc_match: float = 10.0
    credentials: float = 20.0
    cards: float = 20.0
    emails: float = 5.0
    documents: float = 10.0
    cpf: float = 15.0
    cnpj: float = 15.0
    domain: float = 5.0
    threat_actor: float = 20.0
    source_reputation: float = 10.0
    context: float = 10.0
    ioc_quantity: float = 2.0
    recurrence: float = 3.0
    history: float = 5.0


class DetectionCatalog(BaseModel):
    """Container for all dynamic hunting artifacts."""

    keywords: list[str] = Field(default_factory=list)
    watchlists: list[str] = Field(default_factory=list)
    vips: list[str] = Field(default_factory=list)
    threat_actors: list[str] = Field(default_factory=list)
    iocs: list[str] = Field(default_factory=list)
    yara_rules: list[str] = Field(default_factory=list)
    sigma_rules: list[str] = Field(default_factory=list)
