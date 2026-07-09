"""Detection rule strategies (Strategy Pattern).

Each rule implements the core ``DetectionRule`` port and produces zero or more
:class:`DetectionMatch`es for a finding. Rules are interchangeable and composed
by the :class:`DetectionEngine`.
"""

from threat_hunting.infrastructure.detections.rules.regex_rule import RegexRule
from threat_hunting.infrastructure.detections.rules.keyword_rule import KeywordRule
from threat_hunting.infrastructure.detections.rules.ioc_rule import IocMatchRule
from threat_hunting.infrastructure.detections.rules.threat_actor_rule import ThreatActorRule
from threat_hunting.infrastructure.detections.rules.heuristic_rule import HeuristicRule
from threat_hunting.infrastructure.detections.rules.yara_rule import YaraRule

__all__ = [
    "RegexRule",
    "KeywordRule",
    "IocMatchRule",
    "ThreatActorRule",
    "HeuristicRule",
    "YaraRule",
]
