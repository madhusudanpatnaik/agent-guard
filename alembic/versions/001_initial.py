"""Initial schema — captures all tables as of v0.1.0.

Matches ``agentops/models.py`` exactly: multi-tenant ``org_id`` columns on every
tenant-scoped table, per-org unique constraints, the alerts table, and the
connector write-governance columns. Boolean defaults use ``sa.true()`` /
``sa.false()`` so the DDL is portable across SQLite and PostgreSQL, and columns
that carry defaults are NOT NULL, mirroring the ORM's non-Optional annotations.

Revision ID: 001_initial
Revises: None
Create Date: 2026-07-15
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Organizations (tenants)
    op.create_table(
        "organizations",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("name", sa.String(160), unique=True, index=True, nullable=False),
        sa.Column("slug", sa.String(80), unique=True, index=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("contained", sa.Boolean, server_default=sa.false(), nullable=False),
        sa.Column("contained_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("contained_by", sa.String(160), server_default="", nullable=False),
        sa.Column("contained_reason", sa.Text, server_default="", nullable=False),
        sa.Column("contained_until", sa.DateTime(timezone=True), nullable=True),
    )

    # Users (console operators)
    op.create_table(
        "users",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("org_id", sa.Integer, sa.ForeignKey("organizations.id"),
                  nullable=True, index=True),
        sa.Column("email", sa.String(255), unique=True, index=True, nullable=False),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("role", sa.String(32), server_default="admin", nullable=False),
        sa.Column("is_superadmin", sa.Boolean, server_default=sa.false(), nullable=False),
        sa.Column("is_active", sa.Boolean, server_default=sa.true(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # Roles (unique per org, not globally)
    op.create_table(
        "roles",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("org_id", sa.Integer, sa.ForeignKey("organizations.id"),
                  nullable=True, index=True),
        sa.Column("name", sa.String(120), index=True, nullable=False),
        sa.Column("description", sa.Text, server_default="", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("org_id", "name", name="uq_role_org_name"),
    )

    # Policies
    op.create_table(
        "policies",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("role_id", sa.Integer,
                  sa.ForeignKey("roles.id", ondelete="CASCADE"), index=True, nullable=False),
        sa.Column("name", sa.String(160), server_default="", nullable=False),
        sa.Column("effect", sa.String(16), server_default="allow", nullable=False),
        sa.Column("resource", sa.String(512), server_default="*", nullable=False),
        sa.Column("actions", sa.JSON, server_default="[]", nullable=False),
        sa.Column("conditions", sa.JSON, server_default="{}", nullable=False),
        sa.Column("require_approval", sa.Boolean, server_default=sa.false(), nullable=False),
        sa.Column("priority", sa.Integer, server_default="0", nullable=False),
        sa.Column("enabled", sa.Boolean, server_default=sa.true(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # Agents
    op.create_table(
        "agents",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("org_id", sa.Integer, sa.ForeignKey("organizations.id"),
                  nullable=True, index=True),
        sa.Column("name", sa.String(160), index=True, nullable=False),
        sa.Column("description", sa.Text, server_default="", nullable=False),
        sa.Column("role_id", sa.Integer, sa.ForeignKey("roles.id"), index=True, nullable=False),
        sa.Column("api_key_hash", sa.String(128), unique=True, index=True, nullable=False),
        sa.Column("api_key_prefix", sa.String(24), index=True, nullable=False),
        sa.Column("status", sa.String(24), server_default="active", nullable=False),
        sa.Column("owner", sa.String(160), server_default="", nullable=False),
        sa.Column("quota", sa.Integer, server_default="10000", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
    )

    # Audit records (append-only hash chain)
    op.create_table(
        "audit_records",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("seq", sa.Integer, index=True, nullable=False),
        sa.Column("org_id", sa.Integer, sa.ForeignKey("organizations.id"),
                  nullable=True, index=True),
        sa.Column("agent_id", sa.Integer, sa.ForeignKey("agents.id"), nullable=True, index=True),
        sa.Column("agent_name", sa.String(160), server_default="", nullable=False),
        sa.Column("role_name", sa.String(120), server_default="", nullable=False),
        sa.Column("action_type", sa.String(64), server_default="", nullable=False),
        sa.Column("resource", sa.String(512), server_default="", nullable=False),
        sa.Column("decision", sa.String(32), server_default="", nullable=False),
        sa.Column("reason", sa.Text, server_default="", nullable=False),
        sa.Column("payload_hash", sa.String(64), server_default="", nullable=False),
        sa.Column("payload_preview", sa.Text, server_default="", nullable=False),
        sa.Column("dlp_findings", sa.JSON, server_default="[]", nullable=False),
        sa.Column("dlp_count", sa.Integer, server_default="0", index=True, nullable=False),
        sa.Column("billable", sa.Boolean, server_default=sa.true(), index=True, nullable=False),
        sa.Column("matched_policy_id", sa.Integer, nullable=True),
        sa.Column("risk_score", sa.Integer, server_default="0", index=True, nullable=False),
        sa.Column("risk_factors", sa.JSON, server_default="[]", nullable=False),
        sa.Column("prev_hash", sa.String(64), server_default="", nullable=False),
        sa.Column("hash", sa.String(64), index=True, server_default="", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), index=True, nullable=False),
        sa.UniqueConstraint("seq", name="uq_audit_seq"),
    )
    op.create_index("ix_audit_agent_created", "audit_records", ["agent_id", "created_at"])

    # Connectors (unique per org; DB connectors may be writable, row-capped)
    op.create_table(
        "connectors",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("org_id", sa.Integer, sa.ForeignKey("organizations.id"),
                  nullable=True, index=True),
        sa.Column("name", sa.String(120), index=True, nullable=False),
        sa.Column("description", sa.Text, server_default="", nullable=False),
        sa.Column("kind", sa.String(24), server_default="http", nullable=False),
        sa.Column("base_url", sa.String(512), server_default="", nullable=False),
        sa.Column("auth_type", sa.String(16), server_default="none", nullable=False),
        sa.Column("auth_header_name", sa.String(64), server_default="Authorization",
                  nullable=False),
        sa.Column("auth_secret_encrypted", sa.Text, server_default="", nullable=False),
        sa.Column("max_response_bytes", sa.Integer, server_default="1000000", nullable=False),
        sa.Column("writable", sa.Boolean, server_default=sa.false(), nullable=False),
        sa.Column("max_write_rows", sa.Integer, server_default="100", nullable=False),
        sa.Column("enabled", sa.Boolean, server_default=sa.true(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("org_id", "name", name="uq_connector_org_name"),
    )

    # Policy change history (versioning + rollback)
    op.create_table(
        "policy_versions",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("org_id", sa.Integer, sa.ForeignKey("organizations.id"),
                  nullable=True, index=True),
        sa.Column("role_id", sa.Integer, index=True, nullable=False),
        sa.Column("policy_id", sa.Integer, index=True, nullable=False),
        sa.Column("version", sa.Integer, server_default="1", nullable=False),
        sa.Column("action", sa.String(16), server_default="update", nullable=False),
        sa.Column("snapshot", sa.JSON, server_default="{}", nullable=False),
        sa.Column("changed_by", sa.String(160), server_default="", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), index=True, nullable=False),
        sa.UniqueConstraint("policy_id", "version", name="uq_policy_version"),
    )

    # Custom DLP detectors (operator-defined, org-scoped)
    op.create_table(
        "detectors",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("org_id", sa.Integer, sa.ForeignKey("organizations.id"),
                  nullable=True, index=True),
        sa.Column("name", sa.String(120), index=True, nullable=False),
        sa.Column("description", sa.Text, server_default="", nullable=False),
        sa.Column("pattern", sa.String(512), nullable=False),
        sa.Column("severity", sa.String(16), server_default="high", nullable=False),
        sa.Column("enabled", sa.Boolean, server_default=sa.true(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("org_id", "name", name="uq_detector_org_name"),
    )

    # Alerts (detect & respond)
    op.create_table(
        "alerts",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("org_id", sa.Integer, sa.ForeignKey("organizations.id"),
                  nullable=True, index=True),
        sa.Column("severity", sa.String(16), server_default="medium", index=True,
                  nullable=False),
        sa.Column("kind", sa.String(48), server_default="", index=True, nullable=False),
        sa.Column("title", sa.String(200), server_default="", nullable=False),
        sa.Column("detail", sa.Text, server_default="", nullable=False),
        sa.Column("agent_id", sa.Integer, nullable=True, index=True),
        sa.Column("agent_name", sa.String(160), server_default="", nullable=False),
        sa.Column("resource", sa.String(512), server_default="", nullable=False),
        sa.Column("audit_seq", sa.Integer, nullable=True),
        sa.Column("status", sa.String(24), server_default="open", index=True, nullable=False),
        sa.Column("acknowledged_by", sa.String(160), server_default="", nullable=False),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), index=True, nullable=False),
    )

    # Approvals (human-in-the-loop)
    op.create_table(
        "approvals",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("org_id", sa.Integer, sa.ForeignKey("organizations.id"),
                  nullable=True, index=True),
        sa.Column("agent_id", sa.Integer, sa.ForeignKey("agents.id"), index=True, nullable=False),
        sa.Column("agent_name", sa.String(160), server_default="", nullable=False),
        sa.Column("action_type", sa.String(64), server_default="", nullable=False),
        sa.Column("resource", sa.String(512), server_default="", nullable=False),
        sa.Column("payload_preview", sa.Text, server_default="", nullable=False),
        sa.Column("reason", sa.Text, server_default="", nullable=False),
        sa.Column("status", sa.String(24), server_default="pending", index=True, nullable=False),
        sa.Column("resolved_by", sa.String(160), server_default="", nullable=False),
        sa.Column("resolution_note", sa.Text, server_default="", nullable=False),
        sa.Column("audit_record_id", sa.Integer, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), index=True, nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("approvals")
    op.drop_table("alerts")
    op.drop_table("detectors")
    op.drop_table("policy_versions")
    op.drop_table("connectors")
    op.drop_index("ix_audit_agent_created", table_name="audit_records")
    op.drop_table("audit_records")
    op.drop_table("agents")
    op.drop_table("policies")
    op.drop_table("roles")
    op.drop_table("users")
    op.drop_table("organizations")
