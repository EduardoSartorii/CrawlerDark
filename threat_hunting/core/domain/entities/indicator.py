"""Indicator (IOC) — observável técnico associado a um ``Finding``."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import UUID, uuid4

from ..exceptions import InvalidIndicatorError
from ..value_objects import Confidence, IndicatorType

_HASH_RE = {
    IndicatorType.HASH_MD5: re.compile(r"^[a-fA-F0-9]{32}$"),
    IndicatorType.HASH_SHA1: re.compile(r"^[a-fA-F0-9]{40}$"),
    IndicatorType.HASH_SHA256: re.compile(r"^[a-fA-F0-9]{64}$"),
}


@dataclass(slots=True, kw_only=True)
class Indicator:
    """Observável técnico.

    A validação por tipo é feita no construtor para garantir que apenas
    indicadores bem-formados entram no domínio (fail-fast).
    """

    id: UUID = field(default_factory=uuid4)
    type: IndicatorType
    value: str
    confidence: Confidence = field(default_factory=Confidence.medium)
    tags: set[str] = field(default_factory=set)
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    context: dict[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.value or not isinstance(self.value, str):
            raise InvalidIndicatorError("Indicator.value must be a non-empty string")
        self.value = self.value.strip()
        if not self.value:
            raise InvalidIndicatorError("Indicator.value must be a non-empty string")
        self._validate()

    def _validate(self) -> None:
        pattern = _HASH_RE.get(self.type)
        if pattern and not pattern.match(self.value):
            raise InvalidIndicatorError(
                f"Value {self.value!r} is not a valid {self.type.value}"
            )

    def merge_from(self, other: "Indicator") -> None:
        """Enriquecimento incremental: atualiza last_seen, tags e context."""
        if other.type != self.type or other.value.lower() != self.value.lower():
            raise InvalidIndicatorError("Cannot merge indicators of different identity")
        if other.last_seen > self.last_seen:
            self.last_seen = other.last_seen
        if other.first_seen < self.first_seen:
            self.first_seen = other.first_seen
        self.tags.update(other.tags)
        for key, value in other.context.items():
            self.context.setdefault(key, value)
