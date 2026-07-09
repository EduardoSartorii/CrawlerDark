# Threat Hunting Collection Platform

A modular, production-oriented Cyber Threat Intelligence (CTI) collection
platform for Threat Hunting, OSINT, Brand/VIP monitoring, Dark/Deep Web
monitoring, credential/IOC/card/leak/document hunting, campaign & threat-actor
discovery, correlation, scoring, enrichment, export and audit.

Built with **Clean Architecture + DDD + Hexagonal (Ports & Adapters)**. See
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full design.

## Quickstart

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e .
hunt connector list
hunt run sample
hunt export json
```
