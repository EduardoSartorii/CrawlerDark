"""Artifact — evidência binária/textual anexa a um ``Finding``."""

from __future__ import annotations

from dataclasses import dataclass, field
from uuid import UUID, uuid4


@dataclass(slots=True, kw_only=True)
class Artifact:
    """Evidência associada (screenshot, dump HTML, arquivo baixado, ...)."""

    id: UUID = field(default_factory=uuid4)
    kind: str
    filename: str | None = None
    content_type: str | None = None
    sha256: str | None = None
    size_bytes: int | None = None
    storage_uri: str | None = None
    metadata: dict[str, object] = field(default_factory=dict)
