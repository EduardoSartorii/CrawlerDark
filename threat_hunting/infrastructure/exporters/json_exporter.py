"""JSONExporter — grava um arquivo por finding em ``path/YYYY/MM/DD/<id>.json``."""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path

import aiofiles

from ...core.application.dto import FindingDTO
from ...core.domain.entities import Finding


class JSONExporter:
    name = "json"

    def __init__(self, path: str) -> None:
        self._root = Path(path)
        self._root.mkdir(parents=True, exist_ok=True)

    async def export(self, findings: Sequence[Finding]) -> int:
        count = 0
        for f in findings:
            dto = FindingDTO.from_entity(f)
            date_dir = self._root / f"{f.created_at:%Y}" / f"{f.created_at:%m}" / f"{f.created_at:%d}"
            date_dir.mkdir(parents=True, exist_ok=True)
            filepath = date_dir / f"{f.id}.json"
            async with aiofiles.open(filepath, "w", encoding="utf-8") as fh:
                await fh.write(dto.model_dump_json(indent=2))
            count += 1
        return count

    async def health(self) -> bool:
        return self._root.exists() and self._root.is_dir()
