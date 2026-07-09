"""Correlation engine.

Links findings that share indicators/actors into relationships and campaigns,
building the intelligence graph. It attaches ``shared_indicator`` /
``same_actor`` relationships and groups strongly-connected findings into
:class:`Campaign`s.
"""

from threat_hunting.infrastructure.correlation.engine import CorrelationEngine

__all__ = ["CorrelationEngine"]
