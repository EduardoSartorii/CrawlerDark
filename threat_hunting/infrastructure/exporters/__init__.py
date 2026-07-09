"""Exporters implementing the Exporter port (Adapter Pattern).

Each exporter ships findings to one destination. Built-in, dependency-free:
JSON, CSV, STIX 2.1, Webhook. Optional/adapter: MISP (via PyMISP). Others
(OpenCTI, Splunk, OpenSearch, TAXII) follow the same shape.
"""

from threat_hunting.infrastructure.exporters.json_exporter import JsonExporter
from threat_hunting.infrastructure.exporters.csv_exporter import CsvExporter
from threat_hunting.infrastructure.exporters.stix_exporter import StixExporter
from threat_hunting.infrastructure.exporters.webhook_exporter import WebhookExporter
from threat_hunting.infrastructure.exporters.misp_exporter import MispExporter
from threat_hunting.infrastructure.exporters.factory import ExporterFactory

__all__ = [
    "JsonExporter",
    "CsvExporter",
    "StixExporter",
    "WebhookExporter",
    "MispExporter",
    "ExporterFactory",
]
