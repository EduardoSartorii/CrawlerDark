"""The collection pipeline orchestrator.

Owns the mandatory stage ordering and runs each decoupled
:class:`~threat_hunting.core.application.ports.pipeline.PipelineStage` against a
shared :class:`PipelineContext`, publishing domain events at each transition.
"""

from threat_hunting.core.application.pipeline.orchestrator import PipelineOrchestrator

__all__ = ["PipelineOrchestrator"]
