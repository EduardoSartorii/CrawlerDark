"""ExporterFactory — instancia exporters conforme ``config/exporters.yaml``."""

from __future__ import annotations

from ...core.domain.ports import ExporterPort
from ..config.schemas import ExporterConfig
from .csv_exporter import CSVExporter
from .json_exporter import JSONExporter
from .misp_exporter import MISPExporter
from .opencti_exporter import OpenCTIExporter
from .opensearch_exporter import OpenSearchExporter
from .splunk_exporter import SplunkExporter
from .stix_exporter import STIXExporter
from .webhook_exporter import WebhookExporter


class ExporterFactory:
    """Constrói apenas os exporters habilitados na configuração."""

    def build_all(self, configs: dict[str, ExporterConfig]) -> dict[str, ExporterPort]:
        exporters: dict[str, ExporterPort] = {}
        for name, cfg in configs.items():
            if not cfg.enabled:
                continue
            data = cfg.model_dump()
            data.pop("enabled", None)
            exporter = self._build_one(name, data)
            if exporter is not None:
                exporters[name] = exporter
        return exporters

    def _build_one(self, name: str, options: dict[str, object]) -> ExporterPort | None:
        match name:
            case "json":
                return JSONExporter(path=str(options.get("path", "./data/exports/json")))
            case "csv":
                return CSVExporter(path=str(options.get("path", "./data/exports/csv")))
            case "stix":
                return STIXExporter(path=str(options.get("path", "./data/exports/stix")))
            case "misp":
                return MISPExporter(
                    url=str(options.get("url") or "") or None,
                    key=str(options.get("key") or "") or None,
                    verify_tls=bool(options.get("verify_tls", True)),
                    distribution=int(options.get("distribution", 0) or 0),
                    default_event_id=(
                        str(options.get("default_event_id"))
                        if options.get("default_event_id")
                        else None
                    ),
                )
            case "opencti":
                return OpenCTIExporter(
                    url=str(options.get("url") or ""),
                    token=str(options.get("token") or ""),
                )
            case "splunk":
                return SplunkExporter(
                    hec_url=str(options.get("hec_url") or ""),
                    hec_token=str(options.get("hec_token") or ""),
                    index=str(options.get("index", "threat_hunting")),
                )
            case "opensearch":
                return OpenSearchExporter(
                    url=str(options.get("url") or ""),
                    index=str(options.get("index", "threat-hunting-findings")),
                    user=(str(options["user"]) if options.get("user") else None),
                    password=(str(options["password"]) if options.get("password") else None),
                )
            case "webhook":
                return WebhookExporter(
                    url=str(options.get("url") or ""),
                    hmac_secret=(str(options["hmac_secret"]) if options.get("hmac_secret") else None),
                )
            case "taxii":
                return None  # placeholder — implementação futura
            case _:
                return None
