"""Command-line entry point / orchestrator.

Component responsibility
------------------------
Provide a professional CLI around :class:`~phishing_intel.pipeline.PhishingIntelPipeline`.
Operators submit a sample either inline (``--url`` + ``--html-file`` + one or
more ``--js-file``) or as a JSON batch (``--input samples.json``). The CLI wires
configuration, logging and the database, runs the pipeline and prints a
structured JSON report per sample.

Execution flow
--------------
``cli()`` -> parse args -> ``load_settings`` -> ``configure_logging`` ->
``init_db`` -> build pipeline -> for each sample ``pipeline.process`` -> emit a
JSON report to stdout.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional, Sequence

from phishing_intel.config.settings import load_settings
from phishing_intel.database.session import Database
from phishing_intel.logging_config import configure_logging, get_logger
from phishing_intel.models.findings import PhishingSample
from phishing_intel.pipeline import PhishingIntelPipeline, PipelineOutcome

logger = get_logger(__name__)


def _build_parser() -> argparse.ArgumentParser:
    """Construct the argument parser for the CLI."""

    parser = argparse.ArgumentParser(
        prog="phishing-intel",
        description=(
            "Analyse, correlate and enrich phishing campaigns from CTI partner "
            "artifacts (HTML/JavaScript)."
        ),
    )
    parser.add_argument(
        "--config",
        help="Path to config.yaml (defaults to the bundled configuration).",
        default=None,
    )
    parser.add_argument("--url", help="Suspicious URL to analyse.")
    parser.add_argument("--html-file", help="Path to a file containing the page HTML.")
    parser.add_argument(
        "--js-file",
        action="append",
        default=[],
        help="Path to a JavaScript file (repeatable).",
    )
    parser.add_argument(
        "--input",
        help="Path to a JSON file with a list of samples ({url, html, javascript}).",
    )
    parser.add_argument(
        "--no-db",
        action="store_true",
        help="Skip persistence/correlation (pure analysis mode).",
    )
    return parser


def _load_samples(args: argparse.Namespace) -> List[PhishingSample]:
    """Build the list of :class:`PhishingSample` objects from CLI arguments."""

    samples: List[PhishingSample] = []

    # Batch mode: a JSON list of sample dicts.
    if args.input:
        data = json.loads(Path(args.input).read_text(encoding="utf-8"))
        for entry in data:
            samples.append(PhishingSample.model_validate(entry))
        return samples

    # Inline mode: a single sample from --url / --html-file / --js-file.
    if not args.url:
        raise SystemExit("error: provide --url (with optional --html-file/--js-file) or --input")

    html: Optional[str] = None
    if args.html_file:
        html = Path(args.html_file).read_text(encoding="utf-8")
    javascript = [Path(p).read_text(encoding="utf-8") for p in args.js_file]

    samples.append(PhishingSample(url=args.url, html=html, javascript=javascript))
    return samples


def _outcome_to_report(outcome: PipelineOutcome) -> dict:
    """Render a concise, JSON-serialisable report from a pipeline outcome."""

    result = outcome.result
    return {
        "url": result.url,
        "domain": result.domain,
        "phishing_type": (
            result.classification.primary_type.value if result.classification else None
        ),
        "target_brand": result.brand.target_brand if result.brand else None,
        "kit_fingerprint": (
            result.fingerprint.campaign_fingerprint if result.fingerprint else None
        ),
        "exfiltration": [
            {"destination": d.destination, "channel": d.channel.value, "confidence": d.confidence}
            for d in (result.exfiltration.destinations if result.exfiltration else [])
        ],
        "attribution": {
            "score": outcome.attribution.score,
            "confidence": outcome.attribution.confidence.value,
            "signals": [m.signal for m in outcome.attribution.matches],
        },
        "campaign_id": outcome.campaign_id,
        "tags": outcome.tags,
        "iocs": result.iocs,
        "misp_event_uuid": outcome.misp_event_uuid,
        "evidence_path": outcome.evidence_path,
    }


def run(argv: Optional[Sequence[str]] = None) -> int:
    """Programmatic entry point (returns a process exit code)."""

    args = _build_parser().parse_args(argv)
    settings = load_settings(args.config)
    configure_logging(settings.logging.level, settings.logging.format)

    # Persistence is optional (``--no-db`` runs pure analysis).
    database = None if args.no_db else Database(settings.database.url, echo=settings.database.echo)

    pipeline = PhishingIntelPipeline(settings, database=database)

    samples = _load_samples(args)
    reports = []
    for sample in samples:
        outcome = pipeline.process(sample)
        reports.append(_outcome_to_report(outcome))

    # Emit the machine-readable report to stdout.
    json.dump(reports, sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")
    return 0


def cli() -> None:
    """Console-script wrapper used by the Poetry entry point."""

    raise SystemExit(run())


if __name__ == "__main__":
    cli()
