# Django Admin Preparation

The platform is CLI/scheduler-first but architected for a future Django admin.

## Principles

- Django is a **presentation adapter**, not the owner of domain logic.
- Reuse `UnitOfWorkPort`, use-case handlers and repository ports.
- Entities in `core/domain/entities` map 1:1 to admin-managed resources.

## Planned Admin Sections

| Section | Domain Entity / Port |
|---------|----------------------|
| Connectors | `ConnectorConfig` |
| Keywords / Watchlists | `Watchlist` |
| VIPs | `VipProfile` / Watchlist type VIP |
| Threat Actors | `ThreatActor` |
| Regex / YARA / Sigma | Detection rule YAML + RuleLoader |
| Scheduler | `HuntScheduler` + ConnectorConfig.schedule |
| Proxies / OPSEC | `OpsecProfile` |
| Integrations | ExporterFactory configs |
| Users / Permissions | Django auth + AuditPort |
| Findings | `Finding` |
| Exports | `ExportFindingsHandler` |
| Logs / Metrics / Jobs | structlog, Prometheus, `HuntJob` |

## Suggested Layout

```
threat_hunting/web/
  manage.py
  settings.py
  urls.py
  apps/
    connectors/
    findings/
    governance/
    observability/
```

See `threat_hunting/web/__init__.py` for integration notes.
