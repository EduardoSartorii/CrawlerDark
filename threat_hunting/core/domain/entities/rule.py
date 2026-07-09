"""
Detection Rule Entity.

Represents a single detection rule loaded by the Detection Engine.
Rules are never hardcoded — they are loaded dynamically from storage.

Supported rule types:
    - REGEX: Regular expression pattern
    - YARA: YARA malware detection rule
    - SIGMA: Sigma SIEM rule (adapted for log/text analysis)
    - KEYWORD: Simple keyword match with weight
    - IOC: Direct IOC comparison
    - COMPOSITE: Combination of multiple rule conditions
    - HEURISTIC: Configurable threshold-based detection

Business Rules:
    - Disabled rules are never evaluated
    - Rules have priority (higher = evaluated first)
    - Matching a rule triggers a configurable score boost
    - Rules can target specific connectors or categories
    - All rule changes are audit-logged
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import Field, field_validator

from .base import BaseEntity


class RuleType(StrEnum):
    REGEX = "regex"
    YARA = "yara"
    SIGMA = "sigma"
    KEYWORD = "keyword"
    IOC = "ioc"
    COMPOSITE = "composite"
    HEURISTIC = "heuristic"


class RuleAction(StrEnum):
    """What the engine does when this rule matches."""

    ALERT = "alert"
    BOOST_SCORE = "boost_score"
    SET_SEVERITY = "set_severity"
    TAG = "tag"
    SUPPRESS = "suppress"
    EXPORT = "export"
    NOTIFY = "notify"


class DetectionRule(BaseEntity):
    """
    A detection rule evaluated by the Detection Engine.

    Architectural note: rules are data, not code. The engine interprets them.
    This separation allows non-engineers to add/modify rules without deployments.
    """

    name: str = Field(..., min_length=1)
    rule_type: RuleType
    pattern: str = Field(..., description="The rule pattern (regex, YARA, etc.)")
    action: RuleAction = Field(default=RuleAction.BOOST_SCORE)
    score_boost: float = Field(default=1.0, ge=0.0, le=10.0)
    priority: int = Field(default=50, ge=0, le=100)
    is_active: bool = Field(default=True)
    is_whitelist: bool = Field(default=False, description="Suppresses score if matched")
    description: str = Field(default="")
    author: str = Field(default="")
    tags: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)

    # Scope — if empty, applies to all
    applicable_connectors: list[str] = Field(default_factory=list)
    applicable_categories: list[str] = Field(default_factory=list)
    applicable_source_types: list[str] = Field(default_factory=list)

    # Composite rule logic
    child_rule_ids: list[str] = Field(default_factory=list)
    require_all: bool = Field(default=False, description="AND logic for composite rules")

    # Metadata
    false_positive_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    true_positive_rate: float = Field(default=1.0, ge=0.0, le=1.0)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("name")
    @classmethod
    def strip_name(cls, v: str) -> str:
        return v.strip()

    def enable(self) -> None:
        self.is_active = True
        self.touch()

    def disable(self) -> None:
        self.is_active = False
        self.touch()

    def applies_to_connector(self, connector_id: str) -> bool:
        """True if this rule applies to the given connector (empty = all)."""
        return (
            not self.applicable_connectors
            or connector_id in self.applicable_connectors
        )

    def applies_to_category(self, category: str) -> bool:
        return (
            not self.applicable_categories
            or category in self.applicable_categories
        )

    @property
    def effective_score_boost(self) -> float:
        """Score boost, negated if this is a whitelist rule."""
        if self.is_whitelist:
            return -abs(self.score_boost)
        return self.score_boost

    def __str__(self) -> str:
        status = "ON" if self.is_active else "OFF"
        return f"Rule[{self.rule_type}:{self.name}] ({status}, boost={self.score_boost:.1f})"
