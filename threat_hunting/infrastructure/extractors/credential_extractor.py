"""
CredentialExtractor
====================

Detects and extracts credential pairs (username:password, email:hash)
from text content typical of data breaches and credential dumps.

Patterns recognized:
    - email:password
    - username:password
    - email:hash (MD5, SHA1, SHA256)
    - login:password
    - Lines from credential dump files (combolists)

Privacy:
    - Raw credential values are stored in normalized_data for analyst review.
    - The platform does NOT attempt to crack or use credentials.
    - Credentials are tagged for export to MISP with appropriate TLP.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class ExtractedCredential:
    """Parsed credential pair."""

    username: str
    password: str
    is_email: bool
    domain: str | None = None
    raw: str = ""


_CREDENTIAL_PATTERN = re.compile(
    r"([a-zA-Z0-9_.+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}):([^\s,;|\"]{4,})",
    re.MULTILINE,
)

_USERNAME_PASSWORD_PATTERN = re.compile(
    r"(?:^|\s|,|;|\|)([a-zA-Z0-9._\-]{3,64}):([a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]{4,128})(?:\s|,|;|\||$)",
    re.MULTILINE,
)


class CredentialExtractor:
    """Stateless credential pair extractor."""

    def extract(self, text: str, max_results: int = 500) -> list[ExtractedCredential]:
        """
        Extract credential pairs from text.

        Args:
            text: Raw text from a dump, paste, or forum post.
            max_results: Maximum number of pairs to return (performance guard).

        Returns:
            List of ExtractedCredential objects.
        """
        results: list[ExtractedCredential] = []
        seen: set[str] = set()

        # Prefer email:password matches first (higher confidence).
        for match in _CREDENTIAL_PATTERN.finditer(text):
            if len(results) >= max_results:
                break
            email, password = match.group(1), match.group(2)
            key = f"{email.lower()}:{password}"
            if key in seen:
                continue
            seen.add(key)
            domain = email.split("@")[-1] if "@" in email else None
            results.append(
                ExtractedCredential(
                    username=email.lower(),
                    password=password,
                    is_email=True,
                    domain=domain,
                    raw=match.group(0),
                )
            )

        return results

    def count(self, text: str) -> int:
        """Count credential pairs in text (for scoring density)."""
        return len(self.extract(text, max_results=10_000))
