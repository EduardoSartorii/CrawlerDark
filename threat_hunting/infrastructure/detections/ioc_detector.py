"""IOCListDetector — matcha IOCs do finding contra listas de referência."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from ...core.domain.entities import Finding
from ...core.domain.value_objects import Category, Severity


class IOCListDetector:
    """Compara indicadores do finding com listas de IOC (uma linha, `#` comenta)."""

    def __init__(self, list_paths: Iterable[str]) -> None:
        self._blocked: set[str] = set()
        for path in list_paths:
            self._load(Path(path))

    def _load(self, path: Path) -> None:
        if not path.exists():
            return
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            self._blocked.add(line.lower())

    async def detect(self, finding: Finding) -> Finding:
        hits: list[str] = []
        for ind in finding.indicators:
            if ind.value.lower() in self._blocked:
                hits.append(f"{ind.type.value}:{ind.value}")
                ind.tags.add("ioc-list-hit")
        if not hits:
            return finding
        finding.add_tags("rule:ioc")
        finding.record_event(
            "rule.matched",
            f"IOC list hit ({len(hits)})",
            {"rule_id": "ioc.list", "engine": "ioc", "hits": hits[:20]},
        )
        if finding.category is Category.OTHER:
            finding.category = Category.IOC
        if finding.severity < Severity.HIGH:
            finding.set_severity(Severity.HIGH, "escalated by IOC list match")
        return finding
