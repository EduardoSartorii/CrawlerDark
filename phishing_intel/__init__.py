"""Phishing Intelligence Platform.

A professional Cyber Threat Intelligence (CTI) platform for the analysis,
classification, correlation, enrichment and attribution of phishing campaigns.

Architectural overview
-----------------------
The package is organised into cohesive layers, each with a single
responsibility. Data flows top-to-bottom through the pipeline:

``collectors``  -> Acquire raw artifacts (HTML/SSL/DNS/infra) *only when the
                   partner did not supply them* (secondary flow).
``analyzers``   -> Pure, offline static analysis of the supplied artifacts
                   (DOM, JavaScript, forms, exfiltration, kit fingerprint,
                   brand). This is the *primary* flow.
``correlators`` -> Compare a new sample against historical records to produce
                   an attribution score and link campaigns.
``enrichment``  -> Push findings into MISP (events, attributes, objects, tags).
``database``    -> SQLAlchemy persistence (models, session, repositories).
``models``      -> Pydantic domain models shared across every layer.

The :mod:`phishing_intel.main` module wires these layers into an end-to-end
pipeline and exposes a CLI.
"""

__version__ = "1.0.0"

__all__ = ["__version__"]
