"""Artifact value object.

Responsibility
--------------
Represent a binary or textual attachment linked to a finding (screenshot, paste
body, downloaded file, HTML snapshot). Artifacts carry a content hash so that
storage backends can deduplicate and so exporters (e.g. MISP) can attach files.
"""

from __future__ import annotations

import hashlib

from pydantic import BaseModel, ConfigDict, Field


class Artifact(BaseModel):
    """A piece of evidence associated with a finding."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(min_length=1)
    kind: str = Field(description="e.g. screenshot, file, paste, html, image")
    media_type: str = Field(default="application/octet-stream")
    uri: str | None = Field(default=None, description="Where the artifact is stored.")
    sha256: str | None = Field(default=None, description="Content hash, if computed.")
    size_bytes: int | None = Field(default=None, ge=0)

    @classmethod
    def from_bytes(
        cls, name: str, kind: str, data: bytes, media_type: str = "application/octet-stream"
    ) -> "Artifact":
        """Build an artifact from raw bytes, computing its SHA-256 and size."""
        digest = hashlib.sha256(data).hexdigest()
        return cls(
            name=name,
            kind=kind,
            media_type=media_type,
            sha256=digest,
            size_bytes=len(data),
        )
