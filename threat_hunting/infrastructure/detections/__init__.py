"""Detection engine — rule-based threat signal evaluation."""

from .engine import DetectionEngine, DetectionResult, RuleMatch

__all__ = ["DetectionEngine", "DetectionResult", "RuleMatch"]
