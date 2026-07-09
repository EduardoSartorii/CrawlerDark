"""DetectionRule — regra carregada dinamicamente pelo Detection Engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from uuid import UUID, uuid4

from ..exceptions import InvalidRuleError
from ..value_objects import Category, Confidence, Severity


class RuleKind(str, Enum):
    REGEX = "REGEX"
    YARA = "YARA"
    SIGMA = "SIGMA"
    KEYWORD = "KEYWORD"
    IOC = "IOC"
    HEURISTIC = "HEURISTIC"
    COMPOSITE = "COMPOSITE"


@dataclass(slots=True, kw_only=True)
class DetectionRule:
    """Regra plugável de detecção.

    O ``pattern`` é interpretado conforme o ``kind``:
    * REGEX → padrão PCRE-like;
    * YARA → source de regra YARA;
    * SIGMA → YAML sigma;
    * KEYWORD → lista separada por ``|``;
    * IOC → identificador de lista de IOC;
    * COMPOSITE → expressão sobre ``depends_on`` (ex.: ``r1 AND r2``).
    """

    id: UUID = field(default_factory=uuid4)
    rule_id: str
    kind: RuleKind
    pattern: str
    description: str = ""
    category: Category = Category.OTHER
    severity: Severity = Severity.MEDIUM
    confidence: Confidence = field(default_factory=Confidence.medium)
    tags: set[str] = field(default_factory=set)
    enabled: bool = True
    depends_on: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.rule_id:
            raise InvalidRuleError("DetectionRule.rule_id is required")
        if not self.pattern and self.kind is not RuleKind.COMPOSITE:
            raise InvalidRuleError("DetectionRule.pattern is required for non-composite rules")
