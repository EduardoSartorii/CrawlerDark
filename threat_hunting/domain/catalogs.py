"""Domain catalogs for watchlists and threat hunting assets."""

from __future__ import annotations

from pydantic import BaseModel, Field


class KeywordCatalog(BaseModel):
    """Keywords and expressions used in hunting operations."""

    keywords: list[str] = Field(default_factory=list)
    yara_rules: list[str] = Field(default_factory=list)
    regex_rules: list[str] = Field(default_factory=list)
    sigma_rules: list[str] = Field(default_factory=list)


class IdentityCatalog(BaseModel):
    """Managed identities and entities for monitoring."""

    vips: list[str] = Field(default_factory=list)
    companies: list[str] = Field(default_factory=list)
    executives: list[str] = Field(default_factory=list)
    brands: list[str] = Field(default_factory=list)
    threat_actors: list[str] = Field(default_factory=list)


class ObservableCatalog(BaseModel):
    """Managed observables and IOC lists."""

    domains: list[str] = Field(default_factory=list)
    emails: list[str] = Field(default_factory=list)
    cpf: list[str] = Field(default_factory=list)
    cnpj: list[str] = Field(default_factory=list)
    cards: list[str] = Field(default_factory=list)
    wallets: list[str] = Field(default_factory=list)
    telegram: list[str] = Field(default_factory=list)
    github: list[str] = Field(default_factory=list)
    ioc_lists: list[str] = Field(default_factory=list)


class WatchlistCatalog(BaseModel):
    """Aggregate root for all watchlist artifacts."""

    keywords: KeywordCatalog = Field(default_factory=KeywordCatalog)
    identities: IdentityCatalog = Field(default_factory=IdentityCatalog)
    observables: ObservableCatalog = Field(default_factory=ObservableCatalog)
