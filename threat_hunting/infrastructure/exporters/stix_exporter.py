"""STIXExporter — gera bundles STIX 2.1 mínimos (indicator + observed-data)."""

from __future__ import annotations

import json
import uuid
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ...core.domain.entities import Finding, Indicator
from ...core.domain.value_objects import IndicatorType

_STIX_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")


def _stix_uuid(kind: str, key: str) -> str:
    return f"{kind}--{uuid.uuid5(_STIX_NAMESPACE, f'{kind}:{key}')}"


def _pattern_for(ind: Indicator) -> str | None:
    mapping = {
        IndicatorType.IP: "ipv4-addr:value = '{v}'",
        IndicatorType.DOMAIN: "domain-name:value = '{v}'",
        IndicatorType.URL: "url:value = '{v}'",
        IndicatorType.EMAIL: "email-addr:value = '{v}'",
        IndicatorType.HASH_MD5: "file:hashes.MD5 = '{v}'",
        IndicatorType.HASH_SHA1: "file:hashes.SHA1 = '{v}'",
        IndicatorType.HASH_SHA256: "file:hashes.SHA256 = '{v}'",
    }
    tpl = mapping.get(ind.type)
    if not tpl:
        return None
    return "[" + tpl.format(v=ind.value.replace("'", "\\'")) + "]"


class STIXExporter:
    name = "stix"

    def __init__(self, path: str) -> None:
        self._root = Path(path)
        self._root.mkdir(parents=True, exist_ok=True)

    async def export(self, findings: Sequence[Finding]) -> int:
        if not findings:
            return 0
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        bundle = self._build_bundle(findings)
        outfile = self._root / f"bundle-{stamp}.json"
        outfile.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
        return len(findings)

    async def health(self) -> bool:
        return self._root.exists()

    def _build_bundle(self, findings: Sequence[Finding]) -> dict[str, Any]:
        objects: list[dict[str, Any]] = []
        for f in findings:
            report_id = _stix_uuid("report", str(f.id))
            indicator_ids: list[str] = []
            for ind in f.indicators:
                pattern = _pattern_for(ind)
                if not pattern:
                    continue
                ind_id = _stix_uuid("indicator", f"{ind.type.value}:{ind.value}")
                indicator_ids.append(ind_id)
                objects.append(
                    {
                        "type": "indicator",
                        "spec_version": "2.1",
                        "id": ind_id,
                        "created": ind.first_seen.isoformat(),
                        "modified": ind.last_seen.isoformat(),
                        "name": f"{ind.type.value}:{ind.value}",
                        "indicator_types": ["malicious-activity"],
                        "pattern": pattern,
                        "pattern_type": "stix",
                        "valid_from": ind.first_seen.isoformat(),
                        "confidence": ind.confidence.value,
                        "labels": sorted(ind.tags) or None,
                    }
                )
            objects.append(
                {
                    "type": "report",
                    "spec_version": "2.1",
                    "id": report_id,
                    "created": f.created_at.isoformat(),
                    "modified": f.updated_at.isoformat(),
                    "name": f.title,
                    "description": f.description,
                    "published": f.created_at.isoformat(),
                    "labels": sorted(f.tags) or ["threat-hunting"],
                    "confidence": int(f.confidence),
                    "object_refs": indicator_ids or [report_id],
                    "external_references": (
                        [{"source_name": f.source.source, "url": f.source.url}]
                        if f.source.url
                        else None
                    ),
                }
            )
        return {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": [o for o in objects if o is not None],
        }
