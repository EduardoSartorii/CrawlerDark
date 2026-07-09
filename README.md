# Threat Hunting Collection Platform

Corporate-grade **Threat Hunting Collection Platform** for automated threat discovery, leak hunting, IOC collection, brand monitoring, VIP monitoring, and Dark Web intelligence.

## Architecture

Built on **Clean Architecture**, **DDD**, **Hexagonal Architecture**, and **Event-Driven Design**.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for full architectural documentation.

## Features

- Threat Hunting, OSINT, Brand/VIP Monitoring
- Dark Web & Deep Web Monitoring
- Credential, IOC, Card, Document & Leak Hunting
- Campaign & Threat Actor Discovery
- Detection Engine (Regex, YARA, Sigma, Keywords, IOC, Heuristics)
- Configurable Scoring, Correlation & Deduplication
- Enrichment via VirusTotal, GreyNoise, AbuseIPDB, Shodan, etc.
- Export to MISP, OpenCTI, Splunk, Elastic, STIX/TAXII
- OPSEC layer (proxies, rate limiting, credentials)
- Pluggable connectors with auto-discovery
- Structured logging (structlog), Prometheus metrics, OpenTelemetry tracing

## Quick Start

```bash
# Install dependencies
poetry install

# Run a connector
poetry run hunt run reddit

# Run connector group
poetry run hunt run social
poetry run hunt run darkweb

# Run all connectors
poetry run hunt run all

# Manage connectors
poetry run hunt connector list
poetry run hunt connector enable reddit
poetry run hunt connector disable reddit

# Export findings
poetry run hunt export misp
poetry run hunt export splunk
poetry run hunt export elastic
poetry run hunt export json

# Test scoring
poetry run hunt score test

# Start scheduler
poetry run hunt scheduler run

# Health check
poetry run hunt health
```

## Project Structure

```
threat_hunting/
├── core/           # Domain, application, contracts (ports)
├── infrastructure/ # Connectors, engines, storage, exporters
├── cli/            # Typer CLI
├── config/         # YAML configuration
├── api/            # Future REST API
├── web/            # Future Django admin
└── tests/          # Unit & integration tests
```

## Connectors

Reddit, Facebook, Instagram, X, Telegram, Discord, GitHub, GitLab, RSS, Blogs, Sites, Paste Sites, News, Dark Web, Deep Web, Forums, Marketplaces, Feeds, APIs, MISP, OpenCTI, ThreatFox, GreyNoise, VirusTotal, AbuseIPDB, Shodan, Censys, URLHaus, AlienVault OTX.

## Pipeline

```
Connector → Parser → Extractor → Normalizer → Detection → Scoring →
Correlation → Deduplication → Enrichment → Persistence → Export
```

## Tests

```bash
poetry run pytest --cov=threat_hunting --cov-fail-under=90
```

## License

GPL-3.0-or-later
