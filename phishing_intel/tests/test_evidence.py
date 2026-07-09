"""Unit tests for the evidence store (chain of custody)."""

from __future__ import annotations

import json
from pathlib import Path

from phishing_intel.evidence import EvidenceStore


def test_store_writes_all_artifacts(tmp_path: Path, sample_result) -> None:
    store = EvidenceStore(str(tmp_path))
    directory = store.store(
        sample_result,
        html="<html>evidence</html>",
        scripts=["console.log(1)"],
    )
    directory = Path(directory)
    assert (directory / "page.html").read_text() == "<html>evidence</html>"
    assert "console.log" in (directory / "scripts.js").read_text()
    assert (directory / "iocs.txt").exists()

    manifest = json.loads((directory / "manifest.json").read_text())
    assert manifest["url"] == sample_result.url
    assert manifest["certificate"]["serial_number"] == "0a1b2c3d"
    assert manifest["verdict"]["target_brand"] == "itau"

    analysis = json.loads((directory / "analysis.json").read_text())
    assert analysis["domain"] == "itau-secure.example"


def test_store_without_html(tmp_path: Path, sample_result) -> None:
    store = EvidenceStore(str(tmp_path))
    directory = Path(store.store(sample_result, html=None, scripts=None))
    assert not (directory / "page.html").exists()
    assert (directory / "manifest.json").exists()
