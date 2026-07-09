"""Future API package.

The CLI and scheduler already consume application services through the DI
container; a future FastAPI or Django REST API should reuse the same container.
"""
