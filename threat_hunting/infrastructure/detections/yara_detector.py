"""YaraDetector — usa ``yara-python`` se disponível; caso contrário, no-op.

Mantém a plataforma compatível com ambientes sem YARA instalado, sem falhar.
"""

from __future__ import annotations

from pathlib import Path

from ...core.domain.entities import Finding
from ...core.domain.value_objects import Severity

try:  # yara-python é opcional
    import yara  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover — dependência opcional
    yara = None  # type: ignore[assignment]


class YaraDetector:
    def __init__(self, rules_dir: str) -> None:
        self._enabled = yara is not None
        self._rules = None
        if not self._enabled:
            return
        path = Path(rules_dir)
        if not path.exists():
            return
        sources: dict[str, str] = {}
        for f in path.glob("*.yar"):
            sources[f.stem] = str(f)
        for f in path.glob("*.yara"):
            sources[f.stem] = str(f)
        if sources:
            try:
                self._rules = yara.compile(filepaths=sources)
            except Exception:  # noqa: BLE001 — YARA compilation errors
                self._rules = None

    async def detect(self, finding: Finding) -> Finding:
        if not self._enabled or self._rules is None:
            return finding
        haystack = "\n".join([finding.title, finding.description]).encode(
            "utf-8", errors="replace"
        )
        try:
            matches = self._rules.match(data=haystack)  # type: ignore[union-attr]
        except Exception:  # noqa: BLE001
            return finding
        if not matches:
            return finding
        rule_ids = [m.rule for m in matches]
        finding.add_tags("rule:yara")
        finding.record_event(
            "rule.matched",
            f"YARA rules matched: {', '.join(rule_ids)}",
            {"rule_id": "yara.match", "engine": "yara", "rules": rule_ids},
        )
        if finding.severity < Severity.HIGH:
            finding.set_severity(Severity.HIGH, "escalated by YARA")
        return finding
