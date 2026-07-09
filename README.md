# Threat Hunting Collection Platform

Enterprise modular platform for **Threat Hunting**, **OSINT**, **Brand/VIP Monitoring**,
**Dark/Deep Web**, **IOC/Credential/Card/Leak Hunting**, correlation, scoring and export.

> Architecture documentation: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)

## Stack

Python 3.12 · Poetry · Pydantic V2 · SQLAlchemy 2 · Alembic · httpx · BeautifulSoup4 · lxml ·
PyMISP · Redis · APScheduler · structlog · PyYAML · pytest · Typer · Dependency Injector ·
OpenTelemetry · Prometheus Client

## Architecture

Clean Architecture + DDD + Hexagonal + Event-Driven. Core never depends on infrastructure.

```
Connector → Parser → Extractor → Normalizer → Detection → Scoring →
Correlation → Deduplication → Enrichment → Persistence → Export
```

## Quick Start

```bash
# Install
poetry install

# List connectors
poetry run hunt connector list

# Run hunts
poetry run hunt run reddit
poetry run hunt run github
poetry run hunt run telegram
poetry run hunt run social
poetry run hunt run darkweb
poetry run hunt run all

# Connector lifecycle
poetry run hunt connector enable reddit
poetry run hunt connector disable reddit

# Scheduler (once)
poetry run hunt scheduler run

# Export
poetry run hunt export misp
poetry run hunt export splunk
poetry run hunt export elastic
poetry run hunt export json

# Score test
poetry run hunt score test --text "password dump leak"

# Health
poetry run hunt health
```

## Project Layout

See `docs/ARCHITECTURE.md` for the full structure. Key packages:

| Package | Responsibility |
|---------|----------------|
| `threat_hunting/core/domain` | Entities, VOs, events, repository ports |
| `threat_hunting/core/application` | Commands, use cases, pipeline |
| `threat_hunting/connectors` | Plugin SDK + 29 source connectors |
| `threat_hunting/detections` | Dynamic rule engine (regex/yara/sigma/…) |
| `threat_hunting/scoring` | Configurable weighted scoring |
| `threat_hunting/infrastructure` | DI, OPSEC, persistence, observability |
| `threat_hunting/exporters` | MISP, STIX, Splunk, OpenSearch, … |
| `threat_hunting/cli` | Typer CLI |
| `threat_hunting/web` | Future Django admin (prepared) |

## Configuration

- `config/settings.yaml` — platform settings
- `config/opsec/profiles.yaml` — proxies, UA, rate limits
- `config/scoring.yaml` — score weights
- `config/detection/rules.yaml` — detection rules (no hardcoded rules)
- `config/connectors/*.yaml` — per-connector options

## Tests

```bash
poetry run pytest
```

Coverage target: **≥ 90%**.

## Legacy

The original CrawlerDark scripts under `main.py` / `frameworks/` are preserved for reference.
New development happens in `threat_hunting/`.

## License

GNU GPL (see `LICENSE`).
