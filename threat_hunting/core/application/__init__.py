"""Application layer: use cases, the pipeline orchestrator and the ports.

Depends only on the domain. Everything external (connectors, storage, exporters,
transport, messaging) is expressed here as an abstract *port*; infrastructure
provides the concrete *adapters*.
"""
