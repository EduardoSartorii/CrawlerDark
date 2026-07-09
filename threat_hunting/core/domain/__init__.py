"""Domain layer: the enterprise-wide business rules.

This layer is intentionally free of frameworks and I/O. It models the
ubiquitous language of Threat Intelligence Collection (Finding, Indicator,
ThreatActor, Campaign, ...) and enforces domain invariants through Pydantic
value objects and entities.
"""
