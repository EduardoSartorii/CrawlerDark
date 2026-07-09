"""Dependency-injection composition root."""

from threat_hunting.infrastructure.di.container import Container, build_container

__all__ = ["Container", "build_container"]
