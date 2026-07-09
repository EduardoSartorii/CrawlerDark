"""Keyword / watchlist management.

Implements the core ``KeywordProvider`` port. The :class:`YamlKeywordProvider`
loads watchlists and threat actors from YAML, and the
:class:`InMemoryKeywordProvider` is a programmatic provider for tests and the
future Django admin (which will implement the same port over the database).
"""

from threat_hunting.infrastructure.keywords.provider import (
    InMemoryKeywordProvider,
    YamlKeywordProvider,
)

__all__ = ["InMemoryKeywordProvider", "YamlKeywordProvider"]
