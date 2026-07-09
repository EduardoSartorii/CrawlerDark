"""CSVExporter — dump tabular de findings (linha por finding)."""

from __future__ import annotations

import csv
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path

from ...core.domain.entities import Finding


class CSVExporter:
    name = "csv"

    HEADERS = [
        "id",
        "title",
        "source",
        "connector",
        "url",
        "category",
        "severity",
        "score",
        "confidence",
        "tlp",
        "created_at",
        "tags",
        "indicators",
    ]

    def __init__(self, path: str) -> None:
        self._root = Path(path)
        self._root.mkdir(parents=True, exist_ok=True)

    async def export(self, findings: Sequence[Finding]) -> int:
        if not findings:
            return 0
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        outfile = self._root / f"findings-{stamp}.csv"
        with outfile.open("w", encoding="utf-8", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(self.HEADERS)
            for f in findings:
                writer.writerow(
                    [
                        str(f.id),
                        f.title,
                        f.source.source,
                        f.connector,
                        f.source.url or "",
                        f.category.value,
                        f.severity.name,
                        f"{float(f.score):.2f}",
                        int(f.confidence),
                        f.tlp.value,
                        f.created_at.isoformat(),
                        "|".join(sorted(f.tags)),
                        "|".join(f"{i.type.value}:{i.value}" for i in f.indicators),
                    ]
                )
        return len(findings)

    async def health(self) -> bool:
        return self._root.exists()
