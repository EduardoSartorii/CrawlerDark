"""Detection engine and rule strategies.

The :class:`DetectionEngine` applies a dynamically-loaded set of
:class:`~threat_hunting.core.application.ports.detection.DetectionRule`
strategies (regex, keyword, IOC, threat-actor, heuristic, YARA) to a finding,
honouring whitelist/blacklist and a minimum-match threshold. No rule is
hardcoded in the engine — rules are data/plugins.
"""

from threat_hunting.infrastructure.detections.engine import DetectionEngine
from threat_hunting.infrastructure.detections.loader import RuleLoader

__all__ = ["DetectionEngine", "RuleLoader"]
