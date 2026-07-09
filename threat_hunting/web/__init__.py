"""Future Django admin preparation.

Responsibility
--------------
Reserved package for Django administrative UI. Domain entities and
repository ports are already Django-mappable. This module documents the
integration contract without requiring Django at runtime yet.

Planned admin models
--------------------
Connectors, Keywords, VIPs, Threat Actors, Watchlists, Regex, YARA, Sigma,
Scheduler, Proxies, Integrations, Users, Permissions, Findings, Exports,
Logs, Metrics, Jobs.
"""

DJANGO_INTEGRATION_NOTES = """
1. Create Django project under threat_hunting/web/
2. Map domain entities to Django models OR use repositories from views
3. Reuse UnitOfWorkPort / handlers — Django is a presentation adapter
4. Auth/RBAC via Django auth; AuditPort for governance trail
5. Do NOT put business rules in Django models
"""

__all__ = ["DJANGO_INTEGRATION_NOTES"]
