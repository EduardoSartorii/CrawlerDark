"""Value Objects — imutáveis, comparados por valor.

Regras arquiteturais:
* nenhum VO conhece infraestrutura;
* nenhum VO possui identidade (usa ``frozen=True``);
* toda validação acontece no construtor (fail-fast).
"""

from .category import Category
from .confidence import Confidence
from .indicator_type import IndicatorType
from .score import Score
from .severity import Severity
from .source_ref import SourceRef
from .tlp import TLP

__all__ = [
    "Category",
    "Confidence",
    "IndicatorType",
    "Score",
    "Severity",
    "SourceRef",
    "TLP",
]
