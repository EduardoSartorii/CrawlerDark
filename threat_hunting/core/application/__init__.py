"""Application layer: use cases, ports and the collection pipeline.

This layer orchestrates the domain to fulfil the platform's use cases. It
declares *ports* (abstract contracts, as :class:`typing.Protocol` classes) that
the infrastructure layer implements. It depends only on the domain and never on
concrete adapters, satisfying the Dependency Inversion Principle.
"""
