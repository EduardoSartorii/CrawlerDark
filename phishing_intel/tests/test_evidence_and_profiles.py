"""Testes de armazenamento de evidências e comparação multi-perfil."""

from __future__ import annotations

import json

from phishing_intel.evidence import EvidenceStore
from phishing_intel.profile_comparator import ProfileComparator


def test_evidence_store_persists_artifacts_and_manifest(tmp_path):
    """As evidências devem ser gravadas com manifesto de auditoria."""
    store = EvidenceStore(base_dir=str(tmp_path / "ev"))
    path = store.store(
        url="https://phish.tld",
        html="<html>x</html>",
        javascript="alert(1)",
        analysis_summary={"brand": "itau"},
        certificate_pem="PEMDATA",
    )
    assert path
    manifest = json.loads((tmp_path / "ev").glob("*/manifest.json").__next__().read_text())
    assert manifest["url"] == "https://phish.tld"
    assert manifest["analysis_summary"]["brand"] == "itau"
    assert manifest["has_certificate"] is True


def test_evidence_store_disabled_is_noop():
    """Com armazenamento desabilitado, nenhum caminho é retornado."""
    store = EvidenceStore(enabled=False)
    assert store.store(url="x", html="y") == ""


def test_profile_comparator_detects_cloaking():
    """DOM diferente entre desktop e mobile deve sinalizar cloaking."""
    desktop = "<html><body><form action='/x'><input name='a'></form></body></html>"
    mobile = "<html><body><div>bloqueado</div></body></html>"
    comparison = ProfileComparator().compare(
        {"desktop_chrome": desktop, "iphone_safari": mobile}
    )
    assert comparison.cloaking_suspected is True
    assert comparison.diffs
    assert comparison.diffs[0].dom_changed is True


def test_profile_comparator_no_cloaking_identical():
    """DOM idêntico entre perfis não deve sinalizar cloaking."""
    html = "<html><body><p>igual</p></body></html>"
    comparison = ProfileComparator().compare(
        {"desktop_chrome": html, "android_chrome": html}
    )
    assert comparison.cloaking_suspected is False


def test_profile_comparator_empty_input():
    """Entrada vazia deve retornar comparação vazia sem erro."""
    comparison = ProfileComparator().compare({})
    assert comparison.diffs == []
