"""Configuration and the dependency-injection composition root.

* :mod:`threat_hunting.config.settings` -- the typed settings model, loaded from
  YAML + environment.
* :mod:`threat_hunting.config.container` -- the single place that wires concrete
  adapters to the core ports (Dependency Injection).
"""

from threat_hunting.config.settings import Settings, load_settings
from threat_hunting.config.container import Container

__all__ = ["Settings", "load_settings", "Container"]
