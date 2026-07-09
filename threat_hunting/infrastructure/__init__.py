"""Infrastructure layer: adapters implementing the application ports.

This layer depends on ``core`` (never the other way around). It contains all the
technical detail — connectors, storage, exporters, transport, messaging,
observability and configuration — wired together in :mod:`.di.container`.
"""
