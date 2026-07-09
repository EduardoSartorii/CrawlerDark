"""KeywordDetector — matcha texto contra watchlists (keywords, VIPs, marcas)."""

from __future__ import annotations

from collections.abc import Iterable

from ...core.domain.entities import Finding, WatchlistItem, WatchlistKind
from ...core.domain.value_objects import Category, Severity


_CATEGORY_BY_KIND = {
    WatchlistKind.KEYWORD: Category.OTHER,
    WatchlistKind.BRAND: Category.BRAND,
    WatchlistKind.VIP: Category.VIP,
    WatchlistKind.EXECUTIVE: Category.VIP,
    WatchlistKind.DOMAIN: Category.IOC,
    WatchlistKind.EMAIL: Category.IOC,
    WatchlistKind.CPF: Category.DOCUMENT,
    WatchlistKind.CNPJ: Category.DOCUMENT,
    WatchlistKind.CARD: Category.CARD,
    WatchlistKind.WALLET: Category.IOC,
    WatchlistKind.TELEGRAM: Category.SOCIAL,
    WatchlistKind.GITHUB: Category.LEAK,
    WatchlistKind.THREAT_ACTOR: Category.THREAT_ACTOR,
}


class KeywordDetector:
    def __init__(self, watchlist: Iterable[WatchlistItem]) -> None:
        self._items = [w for w in watchlist if w.enabled]

    async def detect(self, finding: Finding) -> Finding:
        text = "\n".join([finding.title, finding.description])
        highest = finding.severity
        for item in self._items:
            if not item.matches(text):
                continue
            category = _CATEGORY_BY_KIND.get(item.kind, Category.OTHER)
            finding.add_tags(f"watch:{item.kind.value.lower()}", *item.tags)
            finding.record_event(
                "rule.matched",
                f"watchlist {item.kind.value} matched: {item.value}",
                {
                    "rule_id": f"watchlist.{item.kind.value.lower()}",
                    "engine": "keyword",
                    "value": item.value,
                    "kind": item.kind.value,
                },
            )
            if finding.category is Category.OTHER:
                finding.category = category
            if item.kind in {WatchlistKind.VIP, WatchlistKind.EXECUTIVE, WatchlistKind.THREAT_ACTOR}:
                highest = max(highest, Severity.HIGH)
            else:
                highest = max(highest, Severity.MEDIUM)
        if highest != finding.severity:
            finding.set_severity(highest, "escalated by keyword detection")
        return finding
