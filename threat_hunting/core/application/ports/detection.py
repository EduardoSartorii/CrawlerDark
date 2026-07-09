"""Detection rule port.

Responsibility
--------------
Define the contract for a detection strategy (regex, keyword, IOC match, YARA,
Sigma, heuristic). The detection engine loads rules dynamically and applies
each against a finding, collecting :class:`DetectionMatch`es. No rule is
hardcoded in the engine — rules are data/plugins implementing this port
(Strategy Pattern).
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol, runtime_checkable

from threat_hunting.core.domain.entities.finding import Finding
from threat_hunting.core.domain.value_objects.score import DetectionMatch


@runtime_checkable
class DetectionRule(Protocol):
    """Contract for a single detection strategy."""

    rule_id: str
    rule_type: str

    def evaluate(self, finding: Finding) -> Sequence[DetectionMatch]:
        """Return the matches this rule produces against ``finding``."""
        ...
