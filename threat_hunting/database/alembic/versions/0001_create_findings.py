"""create findings table

Revision ID: 0001_create_findings
Revises:
Create Date: 2026-07-09
"""

from alembic import op
import sqlalchemy as sa

revision = "0001_create_findings"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create the canonical findings table."""

    op.create_table(
        "findings",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("content_hash", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=512), nullable=False),
        sa.Column("source", sa.String(length=128), nullable=False),
        sa.Column("connector", sa.String(length=128), nullable=False),
        sa.Column("category", sa.String(length=128), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("score", sa.Float(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.UniqueConstraint("content_hash"),
    )
    op.create_index("ix_findings_content_hash", "findings", ["content_hash"])
    op.create_index("ix_findings_source", "findings", ["source"])
    op.create_index("ix_findings_connector", "findings", ["connector"])


def downgrade() -> None:
    """Drop the canonical findings table."""

    op.drop_index("ix_findings_connector", table_name="findings")
    op.drop_index("ix_findings_source", table_name="findings")
    op.drop_index("ix_findings_content_hash", table_name="findings")
    op.drop_table("findings")
