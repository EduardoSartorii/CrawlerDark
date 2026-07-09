"""Analysis layer (primary flow).

Pure, offline static analyzers that turn supplied HTML/JavaScript artifacts
into structured findings. None of these components perform network I/O, making
them fast, deterministic and safe to run against hostile inputs.
"""

from phishing_intel.analyzers.brand_detector import BrandDetector
from phishing_intel.analyzers.dom_analyzer import DOMAnalyzer
from phishing_intel.analyzers.exfiltration_analyzer import ExfiltrationAnalyzer
from phishing_intel.analyzers.form_classifier import FormClassifier
from phishing_intel.analyzers.javascript_analyzer import JavaScriptAnalyzer
from phishing_intel.analyzers.kit_fingerprint import KitFingerprinter

__all__ = [
    "BrandDetector",
    "DOMAnalyzer",
    "ExfiltrationAnalyzer",
    "FormClassifier",
    "JavaScriptAnalyzer",
    "KitFingerprinter",
]
