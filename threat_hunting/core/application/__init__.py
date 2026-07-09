"""
Application Layer
=================

Orchestrates domain objects and ports to implement use cases.
The application layer:
    - Depends on the domain (entities, ports, events).
    - Does NOT depend on infrastructure.
    - Expresses business workflows as use cases / services.
    - Uses dependency injection to receive port implementations.
"""
