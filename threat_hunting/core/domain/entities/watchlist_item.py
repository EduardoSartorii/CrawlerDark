"""WatchlistItem — item monitorado (keyword, VIP, marca, domínio, ...)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from uuid import UUID, uuid4


class WatchlistKind(str, Enum):
    KEYWORD = "KEYWORD"
    BRAND = "BRAND"
    VIP = "VIP"
    EXECUTIVE = "EXECUTIVE"
    DOMAIN = "DOMAIN"
    EMAIL = "EMAIL"
    CPF = "CPF"
    CNPJ = "CNPJ"
    CARD = "CARD"
    WALLET = "WALLET"
    TELEGRAM = "TELEGRAM"
    GITHUB = "GITHUB"
    THREAT_ACTOR = "THREAT_ACTOR"


@dataclass(slots=True, kw_only=True)
class WatchlistItem:
    id: UUID = field(default_factory=uuid4)
    kind: WatchlistKind
    value: str
    aliases: set[str] = field(default_factory=set)
    tags: set[str] = field(default_factory=set)
    enabled: bool = True
    context: dict[str, object] = field(default_factory=dict)

    def matches(self, text: str) -> bool:
        """Retorna True se o texto contiver o valor ou algum alias."""
        if not text:
            return False
        haystack = text.lower()
        if self.value.lower() in haystack:
            return True
        return any(alias.lower() in haystack for alias in self.aliases)
