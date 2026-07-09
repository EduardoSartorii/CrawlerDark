"""Deduplication engine using deterministic fingerprint strategy."""

from __future__ import annotations

from hashlib import sha256
from typing import Any

from threat_hunting.core.contracts import StageContext


class FingerprintDeduplicationEngine:
    """Remove duplicates by stable hash and key IOC fields."""

    def run(self, items: list[dict[str, Any]], context: StageContext) -> list[dict[str, Any]]:
        """Deduplicate findings in-memory for current execution window."""
        seen: set[str] = set()
        unique_items: list[dict[str, Any]] = []
        for item in items:
            normalized = item.get("normalized_data", {})
            fingerprint = "|".join(
                [
                    str(item.get("title", "")).lower(),
                    str(normalized.get("ioc", "")).lower(),
                    str(normalized.get("domain", "")).lower(),
                    str(normalized.get("email", "")).lower(),
                    str(normalized.get("cpf", "")).lower(),
                    str(normalized.get("card", "")).lower(),
                    str(normalized.get("wallet", "")).lower(),
                    str(normalized.get("threat_actor", "")).lower(),
                    str(normalized.get("campaign", "")).lower(),
                ]
            )
            digest = sha256(fingerprint.encode("utf-8")).hexdigest()
            if digest in seen:
                continue
            seen.add(digest)
            unique_items.append({**item, "metadata": {**item.get("metadata", {}), "fingerprint": digest}})
        return unique_items
