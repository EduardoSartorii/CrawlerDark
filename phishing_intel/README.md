# Phishing Intelligence Platform

Professional Threat Intelligence platform for phishing campaign analysis, classification, correlation, enrichment, and attribution.

## Overview

This platform analyzes phishing artifacts (HTML, JavaScript, IOCs) provided by CTI partners to identify:

- **Campaigns** — clusters of related phishing incidents
- **Operators** — attribution through infrastructure and fingerprint correlation
- **Kit Fingerprints** — reusable phishing kit identification
- **Exfiltration Methods** — credential/data collection endpoints
- **Target Brands** — impersonated institutions

## Architecture

```
phishing_intel/
├── collectors/      # HTML, SSL, DNS, infrastructure collection
├── analyzers/       # DOM, JS, forms, exfiltration, kit, brand analysis
├── correlators/     # Campaign, infrastructure, fingerprint correlation
├── enrichment/      # MISP export, taxonomy mapping, campaign building
├── database/        # SQLAlchemy models, repositories, migrations
├── models/          # Pydantic domain models
├── config/          # Operational configuration
└── main.py          # Pipeline orchestrator
```

## Quick Start

```bash
# Install dependencies
poetry install

# Analyze with partner-provided HTML (primary flow)
poetry run phishing-intel https://phish.example.com --html evidence/page.html --no-misp

# Analyze with collection (secondary flow)
poetry run phishing-intel https://phish.example.com

# Multi-profile analysis
poetry run phishing-intel https://phish.example.com --multi-profile
```

## Configuration

Edit `config/config.yaml` or set environment variables:

- `MISP_API_KEY` — MISP API authentication key

## Testing

```bash
poetry run pytest
```

## OPSEC

- Evidence is preserved before analysis begins
- Complete audit trail for all operations
- Separation between collection and analysis modules
