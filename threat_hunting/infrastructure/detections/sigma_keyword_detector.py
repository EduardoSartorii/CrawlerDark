"""SigmaKeywordDetector — subset "keywords" da spec Sigma.

Sigma completo depende de conversores para o SIEM alvo. Como estamos coletando
texto não-estruturado (news, forums, paste sites), suportamos apenas o modo
"keywords" (mais aplicável ao contexto).
"""

from __future__ import annotations

from pathlib import Path

import yaml

from ...core.domain.entities import Finding
from ...core.domain.value_objects import Severity


class _SigmaKeywordRule:
    __slots__ = ("id", "title", "keywords", "level")

    def __init__(self, path: Path) -> None:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        self.id = str(data.get("id", path.stem))
        self.title = str(data.get("title", path.stem))
        self.level = str(data.get("level", "medium")).lower()
        detection = data.get("detection", {})
        keywords = detection.get("keywords") if isinstance(detection, dict) else None
        self.keywords: list[str] = [str(k).lower() for k in (keywords or [])]


class SigmaKeywordDetector:
    def __init__(self, rules_dir: str) -> None:
        self._rules: list[_SigmaKeywordRule] = []
        path = Path(rules_dir)
        if not path.exists():
            return
        for fp in path.glob("*.yml"):
            try:
                self._rules.append(_SigmaKeywordRule(fp))
            except Exception:  # noqa: BLE001
                continue

    async def detect(self, finding: Finding) -> Finding:
        haystack = ("\n".join([finding.title, finding.description])).lower()
        hits: list[str] = []
        for rule in self._rules:
            if any(k in haystack for k in rule.keywords):
                hits.append(rule.id)
        if not hits:
            return finding
        finding.add_tags("rule:sigma")
        finding.record_event(
            "rule.matched",
            f"Sigma (keywords) rules: {', '.join(hits)}",
            {"rule_id": "sigma.keywords", "engine": "sigma", "rules": hits},
        )
        if finding.severity < Severity.HIGH:
            finding.set_severity(Severity.HIGH, "escalated by Sigma")
        return finding
