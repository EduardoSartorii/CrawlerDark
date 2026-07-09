"""Subpacote de analisadores (fluxo principal).

Responsabilidade
----------------
Executar análise estática completa dos artefatos recebidos (HTML e JS):
extração de DOM, análise de JavaScript, classificação de formulários,
detecção de exfiltração, fingerprint de kit e detecção de marca-alvo.

Estes componentes são o núcleo da plataforma e não dependem de rede — operam
sobre os artefatos já coletados/fornecidos.
"""

from __future__ import annotations

from phishing_intel.analyzers.brand_detector import BrandDetector
from phishing_intel.analyzers.dom_analyzer import DomAnalyzer
from phishing_intel.analyzers.exfiltration_analyzer import ExfiltrationAnalyzer
from phishing_intel.analyzers.form_classifier import FormClassifier
from phishing_intel.analyzers.javascript_analyzer import JavaScriptAnalyzer
from phishing_intel.analyzers.kit_fingerprint import KitFingerprinter

__all__ = [
    "BrandDetector",
    "DomAnalyzer",
    "ExfiltrationAnalyzer",
    "FormClassifier",
    "JavaScriptAnalyzer",
    "KitFingerprinter",
]
