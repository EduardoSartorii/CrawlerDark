"""Shared pytest fixtures and configuration."""

import tempfile

import pytest

from phishing_intel.database.session import init_db


@pytest.fixture(scope="session")
def temp_db():
    """Session-scoped temporary database."""
    with tempfile.NamedTemporaryFile(suffix=".db") as f:
        init_db(f"sqlite:///{f.name}")
        yield f.name
