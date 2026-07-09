"""Infrastructure layer: adapters implementing the core ports.

Everything with I/O, third-party libraries or framework coupling lives here:
connectors, parsers, engines, storage backends, exporters, the OPSEC transport,
the event bus and observability. This layer depends on
:mod:`threat_hunting.core`; the reverse is forbidden by the dependency rule.
"""
