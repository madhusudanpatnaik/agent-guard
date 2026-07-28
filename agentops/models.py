"""SQLAlchemy ORM models — the persistent backbone of the control plane.

Object graph::

    User            console operator (JWT auth) that manages the platform
    Role            a named capability profile assigned to agents
    Policy   n:1    RBAC rule attached to a Role (allow/deny + constraints)
    Agent    n:1    a registered autonomous agent bound to exactly one Role
    AuditRecord      append-only, hash-chained log of every governed decision
    Approval  1:1   human-in-the-loop gate for actions needing sign-off
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# --- Enumerated string values (kept as plain strings for portability) -------

class Effect:
    ALLOW = "allow"
    DENY = "deny"


class Decision:
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class AgentStatus:
    ACTIVE = "active"
    SUSPENDED = "suspended"


class ApprovalStatus:
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"
    USED = "used"  # an approval authorizes exactly one execution, then is consumed


# --- Models -----------------------------------------------------------------

class Organization(Base):
    """A tenant. Every user, role, agent, connector, approval and audit record
    belongs to exactly one organization, and all queries are scoped to it."""

    __tablename__ = "organizations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(160), unique=True, index=True)
    slug: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    # Emergency kill switch: when contained, EVERY agent action in this org is
    # denied at the gateway (a fleet-wide freeze for incident response) without
    # having to suspend each agent individually.
    contained: Mapped[bool] = mapped_column(Boolean, default=False)
    contained_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    contained_by: Mapped[str] = mapped_column(String(160), default="")
    contained_reason: Mapped[str] = mapped_column(Text, default="")
    # Optional auto-expiry: if set, containment lifts itself at this time so a
    # freeze can't be forgotten (a common incident-response footgun). Null = the
    # freeze holds until an operator explicitly resumes.
    contained_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    org_id: Mapped[int | None] = mapped_column(
        ForeignKey("organizations.id"), nullable=True, index=True
    )
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(32), default="admin")  # admin | operator | viewer
    # Platform operator: may create organizations and provision their users.
    is_superadmin: Mapped[bool] = mapped_column(Boolean, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Role(Base):
    __tablename__ = "roles"
    __table_args__ = (UniqueConstraint("org_id", "name", name="uq_role_org_name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    org_id: Mapped[int | None] = mapped_column(
        ForeignKey("organizations.id"), nullable=True, index=True
    )
    name: Mapped[str] = mapped_column(String(120), index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    policies: Mapped[list["Policy"]] = relationship(
        back_populates="role", cascade="all, delete-orphan"
    )
    agents: Mapped[list["Agent"]] = relationship(back_populates="role")


class Policy(Base):
    """A single RBAC rule.

    A policy grants (or denies) a set of ``actions`` on resources matching a
    glob ``resource`` pattern such as ``db:customers:*`` or
    ``http:api.stripe.com/v1/charges``. ``deny`` always overrides ``allow``.
    """

    __tablename__ = "policies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    role_id: Mapped[int] = mapped_column(ForeignKey("roles.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(160), default="")
    effect: Mapped[str] = mapped_column(String(16), default=Effect.ALLOW)

    # Glob patterns. "*" matches within a segment; "**" matches across segments.
    resource: Mapped[str] = mapped_column(String(512), default="*")
    # List of action verbs e.g. ["read", "write"] or ["*"].
    actions: Mapped[list] = mapped_column(JSON, default=list)

    # Optional structured constraints (see policy.engine for supported keys):
    #   {"max_amount": 500, "require_approval_over": 100,
    #    "time_window": {"start": "09:00", "end": "17:00"},
    #    "rate_limit": {"count": 5, "per_seconds": 60}}
    conditions: Mapped[dict] = mapped_column(JSON, default=dict)

    require_approval: Mapped[bool] = mapped_column(Boolean, default=False)
    # Higher priority wins on conflicting matches (deny still overrides allow).
    priority: Mapped[int] = mapped_column(Integer, default=0)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    role: Mapped["Role"] = relationship(back_populates="policies")


class Agent(Base):
    __tablename__ = "agents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    org_id: Mapped[int | None] = mapped_column(
        ForeignKey("organizations.id"), nullable=True, index=True
    )
    name: Mapped[str] = mapped_column(String(160), index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    role_id: Mapped[int] = mapped_column(ForeignKey("roles.id"), index=True)

    # We store only a hash of the API key; the plaintext is shown once.
    api_key_hash: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    api_key_prefix: Mapped[str] = mapped_column(String(24), index=True)

    status: Mapped[str] = mapped_column(String(24), default=AgentStatus.ACTIVE)
    owner: Mapped[str] = mapped_column(String(160), default="")
    quota: Mapped[int] = mapped_column(Integer, default=10_000)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    role: Mapped["Role"] = relationship(back_populates="agents")


class AuditRecord(Base):
    """Append-only, hash-chained ledger entry.

    Each record commits to the previous one via ``prev_hash`` so that any
    tampering with historic rows is cryptographically detectable by re-walking
    the chain (see :mod:`agentops.audit.ledger`).
    """

    __tablename__ = "audit_records"
    __table_args__ = (
        UniqueConstraint("seq", name="uq_audit_seq"),
        # Backs the rolling per-agent quota / rate-limit COUNT(*) queries.
        Index("ix_audit_agent_created", "agent_id", "created_at"),
        # Policy analytics (analysis / recommendations / impact preview) filter by
        # (role_name, org_id); without this the ledger is table-scanned and the
        # cost grows with total history rather than with the role's own traffic.
        Index("ix_audit_role_org", "role_name", "org_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    seq: Mapped[int] = mapped_column(Integer, index=True)  # 0-based position in the chain

    org_id: Mapped[int | None] = mapped_column(
        ForeignKey("organizations.id"), nullable=True, index=True
    )
    agent_id: Mapped[int | None] = mapped_column(ForeignKey("agents.id"), nullable=True, index=True)
    agent_name: Mapped[str] = mapped_column(String(160), default="")
    role_name: Mapped[str] = mapped_column(String(120), default="")

    action_type: Mapped[str] = mapped_column(String(64), default="")
    resource: Mapped[str] = mapped_column(String(512), default="")
    decision: Mapped[str] = mapped_column(String(32), default="")
    reason: Mapped[str] = mapped_column(Text, default="")

    # SHA-256 of the raw payload (integrity) plus a redacted preview (privacy).
    payload_hash: Mapped[str] = mapped_column(String(64), default="")
    payload_preview: Mapped[str] = mapped_column(Text, default="")
    dlp_findings: Mapped[list] = mapped_column(JSON, default=list)
    # Denormalized finding count so "DLP incident" queries stay a simple index scan.
    dlp_count: Mapped[int] = mapped_column(Integer, default=0, index=True)
    # True for an agent's primary requested action; False for derivative rows
    # (upstream results, human approvals) that must NOT count against quota/rate.
    billable: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    matched_policy_id: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Adaptive risk score (0–100) + explanatory factors for this decision.
    # Deliberately NOT part of the hash commitment (see audit.ledger._hashable_view):
    # risk is derived analytics, not a governance fact, so recording it must never
    # affect chain integrity or invalidate existing ledgers.
    risk_score: Mapped[int] = mapped_column(Integer, default=0, index=True)
    risk_factors: Mapped[list] = mapped_column(JSON, default=list)

    prev_hash: Mapped[str] = mapped_column(String(64), default="")
    hash: Mapped[str] = mapped_column(String(64), index=True, default="")

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class ConnectorAuth:
    NONE = "none"
    BEARER = "bearer"
    HEADER = "header"
    BASIC = "basic"


class Connector(Base):
    """An upstream system the plane can call on an agent's behalf.

    The plane holds the credential (encrypted); agents reference the connector by
    name and never receive the secret. This is what makes enforcement real — an
    agent cannot reach the upstream directly because it has neither the base URL's
    trust nor the credential.
    """

    __tablename__ = "connectors"
    __table_args__ = (UniqueConstraint("org_id", "name", name="uq_connector_org_name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    org_id: Mapped[int | None] = mapped_column(
        ForeignKey("organizations.id"), nullable=True, index=True
    )
    name: Mapped[str] = mapped_column(String(120), index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    kind: Mapped[str] = mapped_column(String(24), default="http")  # http (db/grpc: roadmap)
    base_url: Mapped[str] = mapped_column(String(512), default="")

    auth_type: Mapped[str] = mapped_column(String(16), default=ConnectorAuth.NONE)
    auth_header_name: Mapped[str] = mapped_column(String(64), default="Authorization")
    # Encrypted at rest (see agentops.vault). Never returned by the API.
    auth_secret_encrypted: Mapped[str] = mapped_column(Text, default="")

    # Cap response bodies scanned/returned (bytes) to bound DLP work.
    max_response_bytes: Mapped[int] = mapped_column(Integer, default=1_000_000)
    # Database connectors are read-only unless explicitly made writable, and a
    # single write may not affect more than max_write_rows (else it is rolled back).
    writable: Mapped[bool] = mapped_column(Boolean, default=False)
    max_write_rows: Mapped[int] = mapped_column(Integer, default=100)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class PolicyVersion(Base):
    """Immutable change history for a policy — governance of the governance.

    Every create / update / delete / rollback of a :class:`Policy` records a
    snapshot here so an operator can review who changed what and, if a change
    caused problems, roll a policy back to any prior state. ``policy_id`` is a
    plain int (not a FK) so a policy's history survives its deletion.
    """

    __tablename__ = "policy_versions"
    # A version number is unique per policy — turns a concurrent-edit race into a
    # hard IntegrityError (retried in history.record) instead of two rows sharing
    # a version with different snapshots (which would make rollback ambiguous).
    __table_args__ = (UniqueConstraint("policy_id", "version", name="uq_policy_version"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    org_id: Mapped[int | None] = mapped_column(
        ForeignKey("organizations.id"), nullable=True, index=True
    )
    role_id: Mapped[int] = mapped_column(Integer, index=True)
    policy_id: Mapped[int] = mapped_column(Integer, index=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    action: Mapped[str] = mapped_column(String(16), default="update")  # create|update|delete|rollback
    snapshot: Mapped[dict] = mapped_column(JSON, default=dict)
    changed_by: Mapped[str] = mapped_column(String(160), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class Detector(Base):
    """An operator-defined DLP detector — extend scanning without a code change.

    Custom detectors are org-scoped and merged with the built-in detector set on
    the request-scan path, so a team can add a house secret format (an internal
    token prefix, an employee-id pattern) and have it blocked on egress just like
    the built-ins, without forking the DLP engine.
    """

    __tablename__ = "detectors"
    __table_args__ = (UniqueConstraint("org_id", "name", name="uq_detector_org_name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    org_id: Mapped[int | None] = mapped_column(
        ForeignKey("organizations.id"), nullable=True, index=True
    )
    name: Mapped[str] = mapped_column(String(120), index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    pattern: Mapped[str] = mapped_column(String(512))  # a Python regex
    severity: Mapped[str] = mapped_column(String(16), default="high")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AlertSeverity:
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertStatus:
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"


class Alert(Base):
    """A detected risk/anomaly worth a human's attention (with optional webhook)."""

    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    org_id: Mapped[int | None] = mapped_column(
        ForeignKey("organizations.id"), nullable=True, index=True
    )
    severity: Mapped[str] = mapped_column(String(16), default=AlertSeverity.MEDIUM, index=True)
    kind: Mapped[str] = mapped_column(String(48), default="", index=True)
    title: Mapped[str] = mapped_column(String(200), default="")
    detail: Mapped[str] = mapped_column(Text, default="")

    agent_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    agent_name: Mapped[str] = mapped_column(String(160), default="")
    resource: Mapped[str] = mapped_column(String(512), default="")
    audit_seq: Mapped[int | None] = mapped_column(Integer, nullable=True)

    status: Mapped[str] = mapped_column(String(24), default=AlertStatus.OPEN, index=True)
    acknowledged_by: Mapped[str] = mapped_column(String(160), default="")
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class Approval(Base):
    __tablename__ = "approvals"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    org_id: Mapped[int | None] = mapped_column(
        ForeignKey("organizations.id"), nullable=True, index=True
    )
    agent_id: Mapped[int] = mapped_column(ForeignKey("agents.id"), index=True)
    agent_name: Mapped[str] = mapped_column(String(160), default="")

    action_type: Mapped[str] = mapped_column(String(64), default="")
    resource: Mapped[str] = mapped_column(String(512), default="")
    payload_preview: Mapped[str] = mapped_column(Text, default="")
    reason: Mapped[str] = mapped_column(Text, default="")

    status: Mapped[str] = mapped_column(String(24), default=ApprovalStatus.PENDING, index=True)
    resolved_by: Mapped[str] = mapped_column(String(160), default="")
    resolution_note: Mapped[str] = mapped_column(Text, default="")

    audit_record_id: Mapped[int | None] = mapped_column(Integer, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
