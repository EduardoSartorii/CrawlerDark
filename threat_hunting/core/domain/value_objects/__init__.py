"""Immutable domain value objects.

Value objects have no identity of their own; two instances with the same
attributes are considered equal. They are the building blocks of the entities
and carry their own validation/normalisation rules, keeping the model rich
(non-anemic) and always valid by construction.
"""

from threat_hunting.core.domain.value_objects.indicator import Indicator
from threat_hunting.core.domain.value_objects.artifact import Artifact
from threat_hunting.core.domain.value_objects.relationship import Relationship
from threat_hunting.core.domain.value_objects.timeline import TimelineEvent
from threat_hunting.core.domain.value_objects.score import Score, DetectionMatch

__all__ = [
    "Indicator",
    "Artifact",
    "Relationship",
    "TimelineEvent",
    "Score",
    "DetectionMatch",
]
