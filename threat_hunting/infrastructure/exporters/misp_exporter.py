"""MISP exporter (auto-export capable).

Responsibility
--------------
Push high-value findings to a MISP instance as events/attributes. This is the
exporter wired into the pipeline's automatic threshold export: when a finding's
score crosses the configured threshold it is pushed to MISP without operator
action.

Design notes
------------
* ``pymisp`` is an optional dependency. When it (or connectivity/credentials)
  is missing, the exporter degrades to a **dry-run** that serialises the MISP
  payload to disk and logs it, so pipelines never fail because MISP is absent.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path

from threat_hunting.core.application.ports.exporter import ExporterPort
from threat_hunting.core.domain.entities import Finding
from threat_hunting.core.domain.enums import IndicatorType
from threat_hunting.infrastructure.observability.logging import get_logger

# MISP attribute type per indicator type.
_MISP_TYPE = {
    IndicatorType.IPV4: "ip-dst",
    IndicatorType.DOMAIN: "domain",
    IndicatorType.URL: "url",
    IndicatorType.EMAIL: "email-src",
    IndicatorType.MD5: "md5",
    IndicatorType.SHA1: "sha1",
    IndicatorType.SHA256: "sha256",
    IndicatorType.BTC_WALLET: "btc",
}


class MispExporter(ExporterPort):
    """Exports findings to MISP (or a dry-run payload when unavailable)."""

    name = "misp"

    def __init__(
        self,
        *,
        url: str | None = None,
        key: str | None = None,
        event_id: str | None = None,
        output_dir: str | Path = "exports",
        verify_tls: bool = True,
    ) -> None:
        self._url = url
        self._key = key
        self._event_id = event_id
        self._dir = Path(output_dir)
        self._verify_tls = verify_tls
        self._log = get_logger("threat_hunting.export.misp")

    def supports_auto_export(self) -> bool:
        """MISP is the automatic threshold-export destination."""
        return True

    def export(self, findings: Sequence[Finding]) -> int:
        """Push findings to MISP, or serialise a dry-run payload if unavailable."""
        payloads = [self._to_misp_event(f) for f in findings]
        client = self._client()
        if client is None:
            return self._dry_run(payloads)
        exported = 0
        for finding, payload in zip(findings, payloads):
            try:
                self._push(client, finding, payload)
                exported += 1
            except Exception as exc:  # noqa: BLE001 - never break the pipeline
                self._log.warning("misp_push_failed", error=str(exc))
        return exported

    # -- internals ---------------------------------------------------------

    def _client(self):
        """Return a PyMISP client or ``None`` when unavailable/unconfigured."""
        if not (self._url and self._key):
            return None
        try:
            from pymisp import PyMISP  # type: ignore

            return PyMISP(self._url, self._key, ssl=self._verify_tls)
        except Exception as exc:  # noqa: BLE001 - pymisp/conn optional
            self._log.info("misp_unavailable_dry_run", error=str(exc))
            return None

    def _push(self, client, finding: Finding, payload: dict) -> None:
        """Add attributes to an existing event or create a new one."""
        from pymisp import MISPEvent  # type: ignore

        if self._event_id:
            for attribute in payload["Attribute"]:
                client.add_attribute(self._event_id, attribute)
            return
        event = MISPEvent()
        event.from_dict(**{"info": payload["info"], "Attribute": payload["Attribute"]})
        client.add_event(event)

    def _dry_run(self, payloads: list[dict]) -> int:
        """Serialise MISP payloads to disk when a live push is not possible."""
        self._dir.mkdir(parents=True, exist_ok=True)
        target = self._dir / "misp_events.json"
        target.write_text(json.dumps(payloads, indent=2), encoding="utf-8")
        self._log.info("misp_dry_run", events=len(payloads), path=str(target))
        return len(payloads)

    @staticmethod
    def _to_misp_event(finding: Finding) -> dict:
        """Map a finding to a MISP event dict with typed attributes."""
        attributes = []
        for indicator in finding.indicators:
            misp_type = _MISP_TYPE.get(indicator.type)
            if misp_type:
                attributes.append(
                    {
                        "type": misp_type,
                        "value": indicator.value,
                        "to_ids": True,
                        "comment": f"from {finding.connector} (score {finding.score})",
                    }
                )
        return {
            "info": finding.title,
            "threat_level_id": 2,
            "analysis": 1,
            "Attribute": attributes,
            "Tag": [{"name": t} for t in finding.tags],
        }
