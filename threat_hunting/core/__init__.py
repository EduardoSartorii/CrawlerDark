"""Business core of the platform.

The core is split into two inward-pointing layers:

* :mod:`threat_hunting.core.domain` -- entities, value objects, domain events
  and exceptions. Depends on nothing but the standard library and Pydantic.
* :mod:`threat_hunting.core.application` -- ports (abstract contracts), the
  collection pipeline and use-case services. Depends only on the domain.

Following the Clean Architecture dependency rule, **nothing in this package may
import from** :mod:`threat_hunting.infrastructure`.
"""
