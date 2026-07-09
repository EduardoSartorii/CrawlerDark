"""External plugin namespace for drop-in connectors.

Any module placed here that defines a :class:`BaseConnector` subclass is
discovered automatically by the :class:`ConnectorRegistry`. This is the
supported way to add proprietary/private connectors without forking the
platform or touching the core.
"""
