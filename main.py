"""Command line entrypoint for the phishing intelligence platform."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import yaml

from phishing_intel.database.repositories import CampaignRepository
from phishing_intel.database.session import create_session_factory, session_scope
from phishing_intel.enrichment.misp_client import MispClient
from phishing_intel.models.findings import AnalysisRequest
from phishing_intel.pipeline import PhishingIntelPipeline
from phishing_intel.utils import configure_logging


def load_config(path: Path) -> dict[str, object]:
    """Load YAML configuration for database, evidence, logging, and MISP."""

    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def read_optional_file(path: str | None) -> str | None:
    """Read an optional artifact file as UTF-8 text."""

    return Path(path).read_text(encoding="utf-8") if path else None


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments for partner-supplied artifacts."""

    parser = argparse.ArgumentParser(description="Analyze phishing artifacts and enrich MISP.")
    parser.add_argument("--url", help="Suspicious URL under analysis")
    parser.add_argument("--html-file", help="Path to collected HTML")
    parser.add_argument("--js-file", help="Path to collected JavaScript")
    parser.add_argument("--config", default="phishing_intel/config/config.yaml", help="YAML configuration path")
    parser.add_argument("--no-fetch", action="store_true", help="Do not fetch HTML when no HTML file is provided")
    parser.add_argument("--no-misp", action="store_true", help="Skip MISP enrichment")
    return parser.parse_args()


def main() -> None:
    """Run the phishing intelligence pipeline and print JSON output."""

    args = parse_args()
    config = load_config(Path(args.config))
    configure_logging(bool(config.get("debug", False)))
    misp_config = config.get("misp", {}) or {}
    factory = create_session_factory(str(config.get("database_url", "sqlite:///phishing_intel.db")))
    with session_scope(factory) as session:
        repository = CampaignRepository(session)
        misp_client = MispClient(
            url=misp_config.get("url"),
            api_key=misp_config.get("api_key"),
            verify_tls=bool(misp_config.get("verify_tls", True)),
            dry_run=bool(misp_config.get("dry_run", True)),
        )
        pipeline = PhishingIntelPipeline(
            repository=repository,
            evidence_path=Path(str(config.get("evidence_path", "evidence"))),
            misp_client=misp_client,
        )
        result, misp_response = pipeline.analyze(
            AnalysisRequest(
                url=args.url,
                html=read_optional_file(args.html_file),
                javascript=read_optional_file(args.js_file),
                fetch_if_missing=not args.no_fetch,
            ),
            enrich_misp=not args.no_misp,
        )
        print(json.dumps({"analysis": result.model_dump(mode="json"), "misp": misp_response}, indent=2))


if __name__ == "__main__":
    main()