"""
Rule Entity
===========

Represents a detection rule loaded dynamically by the Detection Engine.
Rules are first-class entities so they can be managed (enabled/disabled,
versioned, tagged) without code changes.

Rule types:
- REGEX  — compiled regular expression pattern
- YARA   — YARA rule for binary/text matching
- SIGMA  — Sigma rule (converted to query at load time)
- KEYWORD — simple string/phrase match
- IOC    — match against a list of known IOC values
- COMPOSITE — logical combination of other rules (AND / OR / NOT)

Domain rules:
- A disabled rule is loaded but never evaluated.
- Rule priority determines the order of evaluation.
- match_count is incremented by the Detection Engine on every hit.
- Rules MUST be loaded from files — never hardcoded in source code.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class RuleType(str, Enum):
    """Detection rule type."""

    REGEX = "regex"
    YARA = "yara"
    SIGMA = "sigma"
    KEYWORD = "keyword"
    IOC = "ioc"
    HEURISTIC = "heuristic"
    COMPOSITE = "composite"
    WHITELIST = "whitelist"
    BLACKLIST = "blacklist"
    THRESHOLD = "threshold"


class CompositeOperator(str, Enum):
    """Logical operator for composite rules."""

    AND = "and"
    OR = "or"
    NOT = "not"


class Rule(BaseModel):
    """Detection rule entity."""

    model_config = {"validate_assignment": True}

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    type: RuleType
    description: str = ""
    pattern: str | None = None          # For REGEX, KEYWORD, IOC
    content: str | None = None          # For YARA, SIGMA full rule body
    ioc_list: list[str] = Field(default_factory=list)  # For IOC type
    sub_rules: list[str] = Field(default_factory=list)  # For COMPOSITE
    operator: CompositeOperator = CompositeOperator.AND
    is_enabled: bool = True
    priority: int = Field(default=50, ge=0, le=100)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    score_contribution: float = Field(default=1.0, ge=0.0)
    categories: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    match_count: int = 0
    false_positive_count: int = 0
    last_match: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    author: str = "system"
    version: str = "1.0.0"
    references: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("name")
    @classmethod
    def name_must_not_be_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Rule name must not be empty")
        return v.strip()

    def record_match(self, is_false_positive: bool = False) -> None:
        """Register a detection hit."""
        self.match_count += 1
        self.last_match = datetime.now(timezone.utc)
        self.updated_at = datetime.now(timezone.utc)
        if is_false_positive:
            self.false_positive_count += 1

    @property
    def precision(self) -> float:
        """Estimated precision = 1 - FP_rate."""
        if self.match_count == 0:
            return 1.0
        return 1.0 - (self.false_positive_count / self.match_count)

    def __repr__(self) -> str:
        return f"Rule(name={self.name!r}, type={self.type.value!r}, enabled={self.is_enabled})"
