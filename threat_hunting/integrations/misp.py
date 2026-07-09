"""MISP integration adapter."""

from __future__ import annotations

from collections.abc import Sequence

from pymisp import ExpandedPyMISP, MISPEvent, MISPObject

from threat_hunting.core.domain.entities import Finding
from threat_hunting.exporters.base import BaseExporter


class MISPExporter(BaseExporter):
    """Export high-confidence findings to MISP."""

    name = "misp"

    def __init__(self, url: str, api_key: str, verify_tls: bool = True, event_id: str | None = None) -> None:
        self.client = ExpandedPyMISP(url, api_key, verify_tls)
        self.event_id = event_id

    def export(self, findings: Sequence[Finding]) -> None:
        """Export findings as MISP objects."""

        for finding in findings:
            misp_object = MISPObject(name="threat-hunting-finding")
            misp_object.add_attribute("text", value=finding.title)
            misp_object.add_attribute("comment", value=finding.description)
            for indicator in finding.indicators:
                misp_object.add_attribute(indicator.type.value, value=indicator.value)
            if self.event_id:
                self.client.add_object(self.event_id, misp_object)
            else:
                event = MISPEvent()
                event.info = finding.title
                event.add_object(misp_object)
                self.client.add_event(event)
