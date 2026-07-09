"""Indicator (IOC) value object.

Responsibility
--------------
Represent a single observable of interest (IP, domain, hash, email, wallet,
card, CPF/CNPJ, ...) in a *normalised* form so that deduplication and
correlation are deterministic across the whole platform.

Business rules
--------------
* The ``value`` is always canonicalised (lower-cased where case-insensitive,
  "refanged" from defanged notations such as ``hxxp://`` and ``[.]``).
* Equality/hashing is based on ``(type, value)`` so the same IOC seen twice is
  a single logical indicator regardless of surrounding metadata.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from threat_hunting.core.domain.enums import IndicatorType

# Types whose canonical form is case-insensitive.
_LOWERCASE_TYPES = {
    IndicatorType.DOMAIN,
    IndicatorType.URL,
    IndicatorType.EMAIL,
    IndicatorType.MD5,
    IndicatorType.SHA1,
    IndicatorType.SHA256,
    IndicatorType.IPV6,
}

_DEFANG_REPLACEMENTS = (
    ("hxxps", "https"),
    ("hxxp", "http"),
    ("[.]", "."),
    ("(.)", "."),
    ("[:]", ":"),
    ("[at]", "@"),
    ("[@]", "@"),
    (" dot ", "."),
)


class Indicator(BaseModel):
    """An observable/IOC with a type, canonical value and confidence."""

    model_config = ConfigDict(frozen=True)

    type: IndicatorType
    value: str = Field(min_length=1)
    confidence: int = Field(default=50, ge=0, le=100)
    first_seen: str | None = None
    context: str | None = Field(
        default=None, description="Short human context where the IOC was seen."
    )

    @field_validator("value")
    @classmethod
    def _canonicalise(cls, value: str) -> str:
        """Refang and trim the raw value; casing is folded in ``model_post_init``."""
        cleaned = value.strip()
        lowered = cleaned.lower()
        for token, replacement in _DEFANG_REPLACEMENTS:
            if token in lowered:
                # Perform case-insensitive replacement on the original string.
                cleaned = re.sub(re.escape(token), replacement, cleaned, flags=re.IGNORECASE)
                lowered = cleaned.lower()
        return cleaned

    def model_post_init(self, __context: object) -> None:  # noqa: D401
        """Fold case for case-insensitive indicator types (frozen-safe)."""
        if self.type in _LOWERCASE_TYPES and self.value != self.value.lower():
            object.__setattr__(self, "value", self.value.lower())

    @property
    def key(self) -> str:
        """Stable deduplication/correlation key for this indicator."""
        return f"{self.type.value}:{self.value}"

    def __hash__(self) -> int:  # noqa: D401
        return hash(self.key)

    def __eq__(self, other: object) -> bool:  # noqa: D401
        if not isinstance(other, Indicator):
            return NotImplemented
        return self.key == other.key
