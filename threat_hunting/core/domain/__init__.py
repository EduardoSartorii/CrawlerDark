"""
Core Domain Layer.

This is the innermost layer of the Clean Architecture.
It contains only pure business logic and domain concepts.

Rules:
    - No imports from infrastructure, connectors, CLI, or web layers
    - No framework dependencies (SQLAlchemy, FastAPI, etc.)
    - No I/O operations (file, network, database)
    - All dependencies point INWARD only
"""
