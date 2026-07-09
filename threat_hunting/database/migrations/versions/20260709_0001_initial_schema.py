"""Initial schema.

Revision ID: 0001_initial
Revises:
Create Date: 2026-07-09
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "findings",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("description", sa.Text, nullable=False, server_default=""),
        sa.Column("source", sa.String(120), nullable=False, index=True),
        sa.Column("connector", sa.String(120), nullable=False, index=True),
        sa.Column("url", sa.String(2048)),
        sa.Column("author", sa.String(256)),
        sa.Column("category", sa.String(60), nullable=False, index=True),
        sa.Column("severity", sa.String(16), nullable=False, index=True),
        sa.Column("score", sa.Float, nullable=False, server_default="0", index=True),
        sa.Column("confidence", sa.Integer, nullable=False, server_default="50"),
        sa.Column("tlp", sa.String(16), nullable=False, server_default="AMBER"),
        sa.Column("dedup_hash", sa.String(128), index=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, index=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("raw_data", sa.JSON, nullable=False),
        sa.Column("normalized_data", sa.JSON, nullable=False),
        sa.Column("metadata", sa.JSON, nullable=False),
        sa.Column("tags", sa.JSON, nullable=False),
        sa.Column("artifacts", sa.JSON, nullable=False),
        sa.Column("relationships", sa.JSON, nullable=False),
        sa.Column("timeline", sa.JSON, nullable=False),
        sa.Column("exported_to", sa.JSON, nullable=False),
    )
    op.create_table(
        "indicators",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("finding_id", sa.String(36), sa.ForeignKey("findings.id", ondelete="CASCADE"), index=True),
        sa.Column("type", sa.String(60), nullable=False, index=True),
        sa.Column("value", sa.String(1024), nullable=False, index=True),
        sa.Column("confidence", sa.Integer, nullable=False, server_default="50"),
        sa.Column("tags", sa.JSON, nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("context", sa.JSON, nullable=False),
    )
    op.create_table(
        "threat_actors",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(256), nullable=False, unique=True, index=True),
        sa.Column("aliases", sa.JSON, nullable=False),
        sa.Column("description", sa.Text, nullable=False, server_default=""),
        sa.Column("motivations", sa.JSON, nullable=False),
        sa.Column("countries", sa.JSON, nullable=False),
        sa.Column("tags", sa.JSON, nullable=False),
        sa.Column("context", sa.JSON, nullable=False),
    )
    op.create_table(
        "watchlist_items",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("kind", sa.String(60), nullable=False, index=True),
        sa.Column("value", sa.String(500), nullable=False, index=True),
        sa.Column("aliases", sa.JSON, nullable=False),
        sa.Column("tags", sa.JSON, nullable=False),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("context", sa.JSON, nullable=False),
    )
    op.create_table(
        "detection_rules",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("rule_id", sa.String(120), nullable=False, unique=True, index=True),
        sa.Column("kind", sa.String(60), nullable=False),
        sa.Column("pattern", sa.Text, nullable=False),
        sa.Column("description", sa.Text, nullable=False, server_default=""),
        sa.Column("category", sa.String(60), nullable=False, server_default="OTHER"),
        sa.Column("severity", sa.String(16), nullable=False, server_default="MEDIUM"),
        sa.Column("confidence", sa.Integer, nullable=False, server_default="50"),
        sa.Column("tags", sa.JSON, nullable=False),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("depends_on", sa.JSON, nullable=False),
    )
    op.create_table(
        "jobs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("connector", sa.String(120), nullable=False, index=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.Column("status", sa.String(30), nullable=False, index=True),
        sa.Column("items_collected", sa.Integer, nullable=False, server_default="0"),
        sa.Column("items_persisted", sa.Integer, nullable=False, server_default="0"),
        sa.Column("errors", sa.JSON, nullable=False),
        sa.Column("metadata", sa.JSON, nullable=False),
    )


def downgrade() -> None:
    op.drop_table("jobs")
    op.drop_table("detection_rules")
    op.drop_table("watchlist_items")
    op.drop_table("threat_actors")
    op.drop_table("indicators")
    op.drop_table("findings")
