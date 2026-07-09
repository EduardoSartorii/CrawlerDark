"""Static file connector (offline collection).

Responsibility
--------------
Ingest intelligence from local files — paste-site dumps, leak archives, exported
forum threads or seeded fixtures. Because it needs no network, it is ideal for
deterministic end-to-end runs, demos and integration tests, and it doubles as a
generic "bring your own data" collector.

Configuration (``options``)
---------------------------
* ``paths``: list of file paths to ingest.
* ``glob``: optional directory + glob (e.g. ``{"dir": "inbox", "pattern": "*.txt"}``).
* ``category``: hunting category label (falls back to ``leak_hunting``).
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from threat_hunting.core.application.dto import RawRecord
from threat_hunting.core.domain.enums import Category
from threat_hunting.infrastructure.connectors.base import BaseConnector


class StaticFileConnector(BaseConnector):
    """Collects raw records from local files (no network required)."""

    name = "static_file"
    source = "static_file"
    default_category = Category.LEAK_HUNTING

    async def collect(self) -> Sequence[RawRecord]:
        """Read each configured file into a raw record."""
        records: list[RawRecord] = []
        for path in self._resolve_paths():
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            records.append(
                self._record(
                    content=content,
                    url=path.as_uri(),
                    metadata={"title": path.name, "path": str(path)},
                    raw={"path": str(path), "bytes": len(content)},
                )
            )
        return records

    def _resolve_paths(self) -> list[Path]:
        """Resolve explicit paths and an optional directory glob."""
        paths: list[Path] = [Path(p) for p in self.options.get("paths", [])]
        glob = self.options.get("glob")
        if isinstance(glob, dict):
            base = Path(glob.get("dir", "."))
            pattern = glob.get("pattern", "*")
            if base.exists():
                paths.extend(sorted(base.glob(pattern)))
        return [p for p in paths if p.is_file()]

    @property
    def category(self) -> Category:  # noqa: D401 - property override
        """Respect a per-connector category override in options."""
        label = self.options.get("category")
        if label:
            try:
                return Category(label)
            except ValueError:
                pass
        return super().category
