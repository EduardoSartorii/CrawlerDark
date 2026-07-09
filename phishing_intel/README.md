# Phishing Intelligence Platform

Professional **Cyber Threat Intelligence (CTI)** platform for the analysis,
classification, correlation, enrichment and **attribution** of phishing
campaigns received from CTI partners.

The platform is *analysis-first*: partners usually already provide the page
HTML/JavaScript, so static analysis is the **primary flow** and live collection
(fetching the HTML) is a **secondary fallback**. It does not just collect IOCs —
it identifies **campaigns, operators, reused infrastructure, kit fingerprints,
exfiltration methods and historical relationships between incidents**.

## Architecture

```
phishing_intel/
├── collectors/      # Secondary flow: fetch HTML + live SSL/DNS/infra facts
├── analyzers/       # Primary flow: DOM, JS, forms, exfiltration, kit, brand
├── correlators/     # Attribution scoring + campaign linkage
├── enrichment/      # MISP client, taxonomy/tag mapping, campaign builder
├── database/        # SQLAlchemy models, session, repositories
├── models/          # Pydantic domain models (findings, campaign, infra)
├── config/          # config.yaml + typed settings loader
├── evidence.py      # OPSEC chain-of-custody evidence store
├── pipeline.py      # End-to-end orchestrator
├── main.py          # CLI entry point
└── tests/           # Unit + integration tests (>=80% coverage)
```

Data flows top-to-bottom: `collectors → analyzers → correlators → enrichment`,
with `models` as the shared contract and `database` providing history.

## Pipeline

1. **Receive** URL + (optional) HTML + JavaScript + metadata (`PhishingSample`).
2. **Analyze** (offline): DOM structure, phishing-type classification,
   JavaScript network/secret extraction, exfiltration destinations + channel,
   kit fingerprint (DOM/asset/script SHA256 + composite `campaign_fingerprint`),
   brand detection.
3. **Enrich** (optional/live): TLS certificate, DNS, ASN/provider/country.
4. **Correlate** against history → weighted **attribution score** (0–100):
   - fingerprint reuse (high weight), certificate reuse (high), same ASN (med),
     same provider (med), same DOM/JS pattern, same brand.
   - bands: `0–39 low`, `40–69 medium`, `70–100 high`.
5. **Persist** campaign/site/certificate/infrastructure/fingerprint history.
6. **Tag** with the local `fraude:*` taxonomy.
7. **Push** a MISP event (attributes + `domain`/`url`/`ip`/`x509`/`file`/
   `http-request` objects + custom `phishing-campaign` object).
8. **Preserve** raw artifacts + analysis in the evidence store.

## Local taxonomy

`fraude:marca=<brand>`, `fraude:objetivo=<type>`, `fraude:campanha=<id>`,
`fraude:infraestrutura=<asn>`, `fraude:criticidade=<level>`,
`fraude:exfiltracao=<channel>`.

## Install (Poetry)

```bash
cd phishing_intel
poetry install
```

## Usage

Single sample from partner artifacts:

```bash
poetry run phishing-intel --url https://itau-secure.example/login \
  --html-file page.html --js-file app.js
```

Batch mode (JSON list of `{url, html, javascript}`):

```bash
poetry run phishing-intel --input samples.json
```

Pure analysis mode (no DB/correlation):

```bash
poetry run phishing-intel --url https://x.example --html-file page.html --no-db
```

Configuration lives in `config/config.yaml`; any value can be overridden with a
`PHISHINTEL_`-prefixed environment variable (e.g. `PHISHINTEL_MISP__ENABLED=true`).

## Tests

```bash
poetry run pytest          # runs with coverage, fails under 80%
```
