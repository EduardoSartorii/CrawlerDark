# Connector SDK

## BaseConnector

Every connector inherits `threat_hunting.connectors.base.BaseConnector` and implements:

- `connect()`
- `collect()`
- `parse()`
- `normalize()`
- `health()`
- `close()`

## Discovery (Plugin Pattern)

`ConnectorRegistry.discover()` walks `threat_hunting.connectors.*` and registers
all `BaseConnector` subclasses. Use `@register_connector` for explicit registration.

**Core is never modified when adding a connector.**

## Adding a New Connector

1. Create `threat_hunting/connectors/<group>/my_source.py`
2. Inherit `SimpleConnector` or `BaseConnector`
3. Set `name`, `category_group`, `default_category`, `opsec_profile_name`
4. Optionally add `config/connectors/my_source.yaml`
5. Run `hunt connectors list` / `hunt run my_source`

## OPSEC

Connectors receive an `OpsecProfile` and `OpsecTransportPort`. They must not
hardcode proxies, User-Agents or credentials.
