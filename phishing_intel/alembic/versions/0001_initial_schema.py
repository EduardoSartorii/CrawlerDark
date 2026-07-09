"""Initial phishing intelligence schema."""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0001_initial_schema"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create initial tables for phishing intelligence platform."""

    op.create_table(
        "campaigns",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("campaign_id", sa.String(length=120), nullable=False),
        sa.Column("score", sa.Integer(), nullable=False),
        sa.Column("confidence", sa.String(length=20), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_campaigns_campaign_id", "campaigns", ["campaign_id"], unique=True)

    op.create_table(
        "phishing_sites",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("domain", sa.String(length=255), nullable=False),
        sa.Column("html_hash", sa.String(length=64), nullable=False),
        sa.Column("javascript_hash", sa.String(length=64), nullable=True),
        sa.Column("campaign_id_fk", sa.Integer(), sa.ForeignKey("campaigns.id"), nullable=True),
    )
    op.create_index("ix_phishing_sites_domain", "phishing_sites", ["domain"])
    op.create_index("ix_phishing_sites_html_hash", "phishing_sites", ["html_hash"])
    op.create_index("ix_phishing_sites_url", "phishing_sites", ["url"])

    op.create_table(
        "certificates",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("serial_number", sa.String(length=255), nullable=False),
        sa.Column("issuer", sa.Text(), nullable=False),
        sa.Column("fingerprint", sa.String(length=128), nullable=False),
        sa.Column("subject", sa.Text(), nullable=False),
        sa.Column("san", sa.JSON(), nullable=False),
        sa.Column("not_before", sa.String(length=80), nullable=False),
        sa.Column("not_after", sa.String(length=80), nullable=False),
        sa.Column("pem", sa.Text(), nullable=False),
    )
    op.create_index("ix_certificates_fingerprint", "certificates", ["fingerprint"])
    op.create_index("ix_certificates_serial_number", "certificates", ["serial_number"])

    op.create_table(
        "infrastructures",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("ip", sa.String(length=50), nullable=False),
        sa.Column("asn", sa.String(length=50), nullable=True),
        sa.Column("provider", sa.String(length=255), nullable=True),
        sa.Column("organization", sa.String(length=255), nullable=True),
        sa.Column("country", sa.String(length=8), nullable=True),
        sa.Column("domain", sa.String(length=255), nullable=False),
    )
    op.create_index("ix_infrastructures_asn", "infrastructures", ["asn"])
    op.create_index("ix_infrastructures_domain", "infrastructures", ["domain"])
    op.create_index("ix_infrastructures_ip", "infrastructures", ["ip"])
    op.create_index("ix_infrastructures_provider", "infrastructures", ["provider"])

    op.create_table(
        "fingerprints",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("dom_hash", sa.String(length=64), nullable=False),
        sa.Column("asset_hash", sa.String(length=64), nullable=False),
        sa.Column("script_hash", sa.String(length=64), nullable=False),
        sa.Column("campaign_fingerprint", sa.String(length=64), nullable=False),
    )
    op.create_index("ix_fingerprints_asset_hash", "fingerprints", ["asset_hash"])
    op.create_index("ix_fingerprints_campaign_fingerprint", "fingerprints", ["campaign_fingerprint"])
    op.create_index("ix_fingerprints_dom_hash", "fingerprints", ["dom_hash"])
    op.create_index("ix_fingerprints_script_hash", "fingerprints", ["script_hash"])

    op.create_table(
        "misp_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("event_uuid", sa.String(length=80), nullable=False),
        sa.Column("event_id", sa.String(length=80), nullable=False),
        sa.Column("campaign_id", sa.String(length=120), nullable=False),
    )
    op.create_index("ix_misp_events_campaign_id", "misp_events", ["campaign_id"])
    op.create_index("ix_misp_events_event_id", "misp_events", ["event_id"])
    op.create_index("ix_misp_events_event_uuid", "misp_events", ["event_uuid"])

    op.create_table(
        "evidence_audit",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("html_hash", sa.String(length=64), nullable=False),
        sa.Column("javascript_hash", sa.String(length=64), nullable=True),
        sa.Column("ssl_fingerprint", sa.String(length=128), nullable=True),
        sa.Column("raw_html", sa.Text(), nullable=False),
        sa.Column("raw_javascript", sa.JSON(), nullable=False),
        sa.Column("analysis_result", sa.JSON(), nullable=False),
    )

    op.create_table(
        "profile_comparisons",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("profile_name", sa.String(length=80), nullable=False),
        sa.Column("dom_hash", sa.String(length=64), nullable=False),
        sa.Column("asset_hash", sa.String(length=64), nullable=False),
        sa.Column("script_hash", sa.String(length=64), nullable=False),
        sa.Column("dom_diff", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_profile_comparisons_dom_hash", "profile_comparisons", ["dom_hash"])
    op.create_index("ix_profile_comparisons_profile_name", "profile_comparisons", ["profile_name"])
    op.create_index("ix_profile_comparisons_url", "profile_comparisons", ["url"])


def downgrade() -> None:
    """Drop all tables created by the initial migration."""

    op.drop_index("ix_profile_comparisons_url", table_name="profile_comparisons")
    op.drop_index("ix_profile_comparisons_profile_name", table_name="profile_comparisons")
    op.drop_index("ix_profile_comparisons_dom_hash", table_name="profile_comparisons")
    op.drop_table("profile_comparisons")

    op.drop_table("evidence_audit")

    op.drop_index("ix_misp_events_event_uuid", table_name="misp_events")
    op.drop_index("ix_misp_events_event_id", table_name="misp_events")
    op.drop_index("ix_misp_events_campaign_id", table_name="misp_events")
    op.drop_table("misp_events")

    op.drop_index("ix_fingerprints_script_hash", table_name="fingerprints")
    op.drop_index("ix_fingerprints_dom_hash", table_name="fingerprints")
    op.drop_index("ix_fingerprints_campaign_fingerprint", table_name="fingerprints")
    op.drop_index("ix_fingerprints_asset_hash", table_name="fingerprints")
    op.drop_table("fingerprints")

    op.drop_index("ix_infrastructures_provider", table_name="infrastructures")
    op.drop_index("ix_infrastructures_ip", table_name="infrastructures")
    op.drop_index("ix_infrastructures_domain", table_name="infrastructures")
    op.drop_index("ix_infrastructures_asn", table_name="infrastructures")
    op.drop_table("infrastructures")

    op.drop_index("ix_certificates_serial_number", table_name="certificates")
    op.drop_index("ix_certificates_fingerprint", table_name="certificates")
    op.drop_table("certificates")

    op.drop_index("ix_phishing_sites_url", table_name="phishing_sites")
    op.drop_index("ix_phishing_sites_html_hash", table_name="phishing_sites")
    op.drop_index("ix_phishing_sites_domain", table_name="phishing_sites")
    op.drop_table("phishing_sites")

    op.drop_index("ix_campaigns_campaign_id", table_name="campaigns")
    op.drop_table("campaigns")
