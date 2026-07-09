"""Command-line interface (Typer).

Exposes the ``hunt`` command. Each CLI command is a thin Command object
(Command Pattern) that resolves the use-case service from the DI container and
invokes it — no business logic lives in the CLI itself.
"""

from threat_hunting.cli.main import app

__all__ = ["app"]
