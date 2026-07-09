"""Esquema inicial da plataforma phishing_intel.

Revision ID: 0001_initial_schema
Revises:
Create Date: 2026-07-09
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0001_initial_schema"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "campaigns",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("campaign_id", sa.String(64), nullable=False, unique=True),
        sa.Column("score", sa.Float(), nullable=False, server_default="0"),
        sa.Column("confidence", sa.String(16), nullable=False, server_default="low"),
        sa.Column("target_brand", sa.String(128), nullable=True),
        sa.Column("phishing_type", sa.String(64), nullable=True),
        sa.Column("kit_fingerprint", sa.String(128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_campaigns_campaign_id", "campaigns", ["campaign_id"])
    op.create_index("ix_campaigns_kit_fingerprint", "campaigns", ["kit_fingerprint"])

    op.create_table(
        "certificates",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("serial_number", sa.String(128), nullable=False),
        sa.Column("issuer", sa.String(512), nullable=False),
        sa.Column("subject", sa.String(512), nullable=False),
        sa.Column("sha1_fingerprint", sa.String(64), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("san", sa.Text(), nullable=True),
        sa.Column("not_before", sa.DateTime(timezone=True), nullable=True),
        sa.Column("not_after", sa.DateTime(timezone=True), nullable=True),
        sa.Column("raw_pem", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_certificates_serial_number", "certificates", ["serial_number"])
    op.create_index("ix_certificates_fingerprint", "certificates", ["fingerprint"])

    op.create_table(
        "infrastructures",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("ip", sa.String(64), nullable=True),
        sa.Column("asn", sa.String(32), nullable=True),
        sa.Column("provider", sa.String(255), nullable=True),
        sa.Column("domain", sa.String(255), nullable=True),
        sa.Column("country", sa.String(8), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_infrastructures_ip", "infrastructures", ["ip"])
    op.create_index("ix_infrastructures_asn", "infrastructures", ["asn"])

    op.create_table(
        "fingerprints",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("dom_hash", sa.String(64), nullable=False),
        sa.Column("asset_hash", sa.String(64), nullable=False),
        sa.Column("script_hash", sa.String(64), nullable=False),
        sa.Column("campaign_fingerprint", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_fingerprints_dom_hash", "fingerprints", ["dom_hash"])
    op.create_index("ix_fingerprints_campaign_fingerprint", "fingerprints", ["campaign_fingerprint"])

    op.create_table(
        "phishing_sites",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("url", sa.String(2048), nullable=False),
        sa.Column("domain", sa.String(255), nullable=True),
        sa.Column("html_hash", sa.String(64), nullable=True),
        sa.Column("javascript_hash", sa.String(64), nullable=True),
        sa.Column("phishing_type", sa.String(64), nullable=True),
        sa.Column("target_brand", sa.String(128), nullable=True),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("campaign_id", sa.Integer(), sa.ForeignKey("campaigns.id"), nullable=True),
        sa.Column("certificate_id", sa.Integer(), sa.ForeignKey("certificates.id"), nullable=True),
        sa.Column("infrastructure_id", sa.Integer(), sa.ForeignKey("infrastructures.id"), nullable=True),
        sa.Column("fingerprint_id", sa.Integer(), sa.ForeignKey("fingerprints.id"), nullable=True),
    )
    op.create_index("ix_phishing_sites_url", "phishing_sites", ["url"])
    op.create_index("ix_phishing_sites_domain", "phishing_sites", ["domain"])
    op.create_index("ix_phishing_sites_html_hash", "phishing_sites", ["html_hash"])

    op.create_table(
        "misp_events",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("event_uuid", sa.String(64), nullable=False, unique=True),
        sa.Column("event_id", sa.String(32), nullable=True),
        sa.Column("campaign_id", sa.Integer(), sa.ForeignKey("campaigns.id"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_misp_events_event_uuid", "misp_events", ["event_uuid"])

    op.create_table(
        "evidence_records",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("site_id", sa.Integer(), sa.ForeignKey("phishing_sites.id"), nullable=True),
        sa.Column("url", sa.String(2048), nullable=False),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("html_sha256", sa.String(64), nullable=True),
        sa.Column("javascript_sha256", sa.String(64), nullable=True),
        sa.Column("ssl_sha256_fingerprint", sa.String(64), nullable=True),
        sa.Column("source", sa.String(32), nullable=False, server_default="partner_supplied"),
        sa.Column("raw_html_path", sa.String(1024), nullable=True),
        sa.Column("raw_javascript_path", sa.String(1024), nullable=True),
    )

    op.create_table(
        "profile_comparisons",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("site_id", sa.Integer(), sa.ForeignKey("phishing_sites.id"), nullable=True),
        sa.Column("baseline_profile", sa.String(64), nullable=False),
        sa.Column("compared_profile", sa.String(64), nullable=False),
        sa.Column("dom_differs", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("assets_diff", sa.Text(), nullable=True),
        sa.Column("scripts_diff", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "audit_log_entries",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("url", sa.String(2048), nullable=True),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("details", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("audit_log_entries")
    op.drop_table("profile_comparisons")
    op.drop_table("evidence_records")
    op.drop_table("misp_events")
    op.drop_table("phishing_sites")
    op.drop_table("fingerprints")
    op.drop_table("infrastructures")
    op.drop_table("certificates")
    op.drop_table("campaigns")
