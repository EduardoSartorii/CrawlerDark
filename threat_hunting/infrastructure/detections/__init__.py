"""Detection Engine — Strategy Pattern com detectores plugáveis.

Detectores incluídos:
* ``RegexDetector`` — carrega regras de ``config/rules/regex.yaml``.
* ``KeywordDetector`` — usa keywords/brands/vips/threat_actors do watchlists.
* ``IOCListDetector`` — case sensitive-ish match contra listas de IOC.
* ``YaraDetector`` — usa ``yara-python`` se instalado; caso contrário, no-op.
* ``SigmaKeywordDetector`` — implementa apenas o subset "keywords" do Sigma.

O ``CompositeDetectionEngine`` combina todos e implementa ``DetectionEnginePort``.
"""

from .composite import CompositeDetectionEngine
from .ioc_detector import IOCListDetector
from .keyword_detector import KeywordDetector
from .regex_detector import RegexDetector
from .sigma_keyword_detector import SigmaKeywordDetector
from .yara_detector import YaraDetector

__all__ = [
    "CompositeDetectionEngine",
    "IOCListDetector",
    "KeywordDetector",
    "RegexDetector",
    "SigmaKeywordDetector",
    "YaraDetector",
]
