"""Unit tests for the kit fingerprinter."""

from __future__ import annotations

from phishing_intel.analyzers.dom_analyzer import DOMAnalyzer
from phishing_intel.analyzers.kit_fingerprint import KitFingerprinter


def _fp(html: str):
    dom = DOMAnalyzer().analyze(html, "https://x.example")
    return KitFingerprinter().fingerprint(dom)


def test_fingerprint_populated(phishing_html: str) -> None:
    fp = _fp(phishing_html)
    assert fp.dom_hash and len(fp.dom_hash) == 64
    assert fp.asset_hash and len(fp.asset_hash) == 64
    assert fp.script_hash and len(fp.script_hash) == 64
    assert fp.campaign_fingerprint and len(fp.campaign_fingerprint) == 64
    # Path signature captures the /js and /assets directory layout.
    assert any("/js" in p for p in fp.path_signature)


def test_identical_kits_share_fingerprint(phishing_html: str) -> None:
    # Same structure/assets but different form action -> same kit fingerprint,
    # because the fingerprint keys on structure + filenames, not attribute URLs.
    variant = phishing_html.replace("next.php", "gate.php")
    assert _fp(phishing_html).campaign_fingerprint == _fp(variant).campaign_fingerprint


def test_different_assets_change_fingerprint(phishing_html: str) -> None:
    variant = phishing_html.replace("app.min.js", "totally-different-bundle.js")
    assert _fp(phishing_html).campaign_fingerprint != _fp(variant).campaign_fingerprint
