"""Pydantic request/response models for the HTTP API."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


# --- Auth -------------------------------------------------------------------

class LoginRequest(BaseModel):
    email: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: "UserOut"


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    org_id: int | None = None
    email: str
    role: str
    is_active: bool
    is_superadmin: bool = False


# --- Organizations (multi-tenancy) ------------------------------------------

class OrgIn(BaseModel):
    name: str = Field(examples=["Acme Corp"])
    slug: str = Field(examples=["acme"], pattern=r"^[a-z0-9][a-z0-9-]{1,63}$")


class OrgOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    slug: str
    created_at: datetime
    contained: bool = False
    contained_at: datetime | None = None
    contained_by: str = ""
    contained_reason: str = ""
    contained_until: datetime | None = None


class ContainmentRequest(BaseModel):
    contained: bool = Field(description="True to freeze the fleet, False to resume.")
    reason: str = ""
    # Optional auto-expiry: lift the freeze automatically after N minutes.
    duration_minutes: int | None = Field(default=None, ge=1, le=100_000)


class OrgUserIn(BaseModel):
    email: str
    password: str
    role: str = Field(default="admin", pattern="^(admin|operator|viewer)$")


# --- Roles & policies -------------------------------------------------------

class PolicyIn(BaseModel):
    name: str = ""
    effect: str = Field(default="allow", pattern="^(allow|deny)$")
    resource: str = "*"
    actions: list[str] = Field(default_factory=lambda: ["*"])
    conditions: dict[str, Any] = Field(default_factory=dict)
    require_approval: bool = False
    priority: int = 0
    enabled: bool = True


class PolicyOut(PolicyIn):
    model_config = ConfigDict(from_attributes=True)
    id: int
    role_id: int
    created_at: datetime


class PolicyVersionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    role_id: int
    policy_id: int
    version: int
    action: str
    snapshot: dict[str, Any]
    changed_by: str
    created_at: datetime


class RoleIn(BaseModel):
    name: str
    description: str = ""


class RoleUpdate(BaseModel):
    name: str | None = None
    description: str | None = None


class RoleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    description: str
    created_at: datetime
    policies: list[PolicyOut] = Field(default_factory=list)


class PolicyFindingOut(BaseModel):
    kind: str
    severity: str
    message: str
    policy_ids: list[int] = Field(default_factory=list)


class PolicyAnalysisOut(BaseModel):
    role_id: int
    role_name: str
    findings: list[PolicyFindingOut] = Field(default_factory=list)
    unused_policy_ids: list[int] = Field(default_factory=list)
    denial_hotspots: list[dict[str, Any]] = Field(default_factory=list)


class PolicyRecommendationOut(BaseModel):
    resource: str
    actions: list[str]
    denials: int
    confidence: str
    rationale: str


class ApplyRecommendationRequest(BaseModel):
    resource: str
    actions: list[str]
    name: str = ""
    require_approval: bool = False


class PolicyPreviewRequest(BaseModel):
    resource: str
    actions: list[str] = Field(default_factory=lambda: ["*"])


class PolicyImpactOut(BaseModel):
    resource: str
    actions: list[str]
    would_allow: int
    sensitive_allow: int
    sample: list[dict[str, Any]] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


# --- Agents -----------------------------------------------------------------

class AgentIn(BaseModel):
    name: str
    description: str = ""
    role_id: int
    owner: str = ""
    quota: int | None = None


class AgentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    description: str
    role_id: int
    status: str
    owner: str
    quota: int
    api_key_prefix: str
    created_at: datetime
    last_seen_at: datetime | None = None


class AgentCreated(AgentOut):
    api_key: str = Field(description="Shown exactly once — store it securely.")


class ReputationOut(BaseModel):
    agent_id: int
    score: int
    band: str
    factors: list[str] = Field(default_factory=list)
    sample_size: int = 0


class AgentStatusUpdate(BaseModel):
    status: str = Field(pattern="^(active|suspended)$")


class AgentUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    role_id: int | None = None
    owner: str | None = None
    quota: int | None = None


# --- Gateway ----------------------------------------------------------------

class AuthorizeRequest(BaseModel):
    action_type: str = Field(examples=["db.read", "http.post", "payment.transfer"])
    resource: str = Field(examples=["db:customers:read", "http:api.stripe.com/v1/charges"])
    payload: Any = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    # ABAC attributes (resource tags, env context). subject/env are overridden
    # server-side from the authenticated agent + clock and cannot be spoofed.
    attributes: dict[str, Any] = Field(default_factory=dict)


class DLPFindingOut(BaseModel):
    detector: str
    severity: str
    count: int
    sample: str
    path: str = ""


class AuthorizeResponse(BaseModel):
    decision: str
    reason: str
    request_id: int | None = None
    approval_id: int | None = None
    matched_policy_id: int | None = None
    obligations: list[str] = Field(default_factory=list)
    dlp_findings: list[DLPFindingOut] = Field(default_factory=list)
    risk_score: int | None = None
    risk_factors: list[str] = Field(default_factory=list)
    audit_seq: int | None = None
    audit_hash: str | None = None


# --- Connectors -------------------------------------------------------------

class ConnectorIn(BaseModel):
    name: str = Field(examples=["crm", "payments"])
    description: str = ""
    kind: str = Field(default="http",
                      pattern="^(http|database|grpc|kafka|rabbitmq|sqs|websocket)$")
    base_url: str = Field(examples=["http://127.0.0.1:9100"])
    auth_type: str = Field(default="none", pattern="^(none|bearer|header|basic)$")
    auth_header_name: str = "Authorization"
    # Write-only: accepted on create/update, never returned.
    auth_secret: str = ""
    max_response_bytes: int = 1_000_000
    # Database connectors only: allow governed writes (default read-only), and the
    # per-write row-affected cap that triggers a rollback when exceeded.
    writable: bool = False
    max_write_rows: int = 100
    enabled: bool = True


class ConnectorOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    description: str
    kind: str
    base_url: str
    auth_type: str
    auth_header_name: str
    max_response_bytes: int
    writable: bool = False
    max_write_rows: int = 100
    enabled: bool
    created_at: datetime
    has_secret: bool = False


class ConnectorTestResult(BaseModel):
    name: str
    reachable: bool
    status_code: int | None = None
    error: str | None = None


# --- Custom DLP detectors ---------------------------------------------------

class DetectorIn(BaseModel):
    name: str = Field(examples=["acme_internal_token"], pattern=r"^[a-zA-Z0-9_\-]{1,120}$")
    description: str = ""
    pattern: str = Field(examples=[r"ACME-[0-9A-F]{16}"], max_length=512)
    severity: str = Field(default="high", pattern="^(critical|high|medium|low)$")
    enabled: bool = True


class DetectorOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    description: str
    pattern: str
    severity: str
    enabled: bool
    created_at: datetime


class DetectorTestRequest(BaseModel):
    pattern: str = Field(max_length=512)
    sample: str = ""


class DetectorTestResult(BaseModel):
    valid: bool
    matched: bool
    error: str | None = None


class ExecuteRequest(BaseModel):
    connector: str = Field(examples=["crm"])
    method: str = Field(default="GET", examples=["GET", "POST"])
    path: str = Field(default="/", examples=["/customers/1042"])
    headers: dict[str, str] = Field(default_factory=dict)
    body: Any = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    approval_id: int | None = None


class ExecuteResponse(BaseModel):
    executed: bool
    decision: str
    reason: str
    request_id: int | None = None
    approval_id: int | None = None
    status_code: int | None = None
    response_headers: dict[str, str] = Field(default_factory=dict)
    response_body: Any = None
    response_dlp_findings: list[DLPFindingOut] = Field(default_factory=list)
    request_dlp_findings: list[DLPFindingOut] = Field(default_factory=list)
    upstream_error: str | None = None
    audit_seq: int | None = None
    audit_hash: str | None = None


class QueryRequest(BaseModel):
    connector: str = Field(examples=["warehouse"])
    sql: str = Field(examples=["SELECT id, name FROM customers WHERE tier = :tier"])
    params: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)
    approval_id: int | None = None


class QueryResponse(BaseModel):
    executed: bool
    decision: str
    reason: str
    request_id: int | None = None
    approval_id: int | None = None
    columns: list[str] = Field(default_factory=list)
    rows: list[dict] = Field(default_factory=list)
    row_count: int = 0
    response_dlp_findings: list[DLPFindingOut] = Field(default_factory=list)
    error: str | None = None
    audit_seq: int | None = None
    audit_hash: str | None = None


class WriteRequest(BaseModel):
    connector: str = Field(examples=["tickets"])
    sql: str = Field(examples=["UPDATE tickets SET status = :s WHERE id = :id"])
    params: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)
    approval_id: int | None = None


class WriteResponse(BaseModel):
    executed: bool
    decision: str
    reason: str
    request_id: int | None = None
    approval_id: int | None = None
    rows_affected: int = 0
    error: str | None = None
    audit_seq: int | None = None
    audit_hash: str | None = None


class PublishRequest(BaseModel):
    connector: str = Field(examples=["events"])
    topic: str = Field(examples=["orders.created"])
    message: Any = None
    key: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    approval_id: int | None = None


class PublishResponse(BaseModel):
    executed: bool
    decision: str
    reason: str
    request_id: int | None = None
    approval_id: int | None = None
    request_dlp_findings: list[DLPFindingOut] = Field(default_factory=list)
    error: str | None = None
    audit_seq: int | None = None
    audit_hash: str | None = None


# --- Policy simulator (dry-run) ---------------------------------------------

class SimulateRequest(BaseModel):
    action_type: str = Field(examples=["payment.refund"])
    resource: str = Field(examples=["payment:stripe:refund"])
    payload: Any = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    attributes: dict[str, Any] = Field(default_factory=dict)
    # Evaluate against an existing role/agent's live policies…
    role_id: int | None = None
    agent_id: int | None = None
    # …or against an ad-hoc "what-if" policy set (nothing is saved).
    policies: list[PolicyIn] | None = None


class SimulateResponse(BaseModel):
    decision: str
    reason: str
    matched_policy_id: int | None = None
    obligations: list[str] = Field(default_factory=list)
    dlp_findings: list[DLPFindingOut] = Field(default_factory=list)
    is_egress: bool = False
    evaluated_policies: int = 0


# --- Audit ------------------------------------------------------------------

class AuditRecordOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    seq: int
    agent_id: int | None
    agent_name: str
    role_name: str
    action_type: str
    resource: str
    decision: str
    reason: str
    payload_hash: str
    payload_preview: str
    dlp_findings: list[Any]
    matched_policy_id: int | None
    risk_score: int = 0
    risk_factors: list[Any] = Field(default_factory=list)
    prev_hash: str
    hash: str
    created_at: datetime


class ChainStatusOut(BaseModel):
    valid: bool
    length: int
    head_hash: str
    broken_at_seq: int | None = None
    detail: str


# --- Approvals --------------------------------------------------------------

class ApprovalOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    agent_id: int
    agent_name: str
    action_type: str
    resource: str
    payload_preview: str
    reason: str
    status: str
    resolved_by: str
    resolution_note: str
    created_at: datetime
    expires_at: datetime | None = None
    resolved_at: datetime | None = None


class ApprovalDecision(BaseModel):
    approve: bool
    note: str = ""


# --- Alerts -----------------------------------------------------------------

class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    severity: str
    kind: str
    title: str
    detail: str
    agent_id: int | None = None
    agent_name: str
    resource: str
    audit_seq: int | None = None
    status: str
    acknowledged_by: str
    acknowledged_at: datetime | None = None
    created_at: datetime


# --- Compliance reporting ---------------------------------------------------

class FrameworkControlOut(BaseModel):
    id: str
    title: str
    requirement: str
    how: str


class FrameworkOut(BaseModel):
    id: str
    name: str
    controls: list[FrameworkControlOut] = Field(default_factory=list)


class ComplianceReportRequest(BaseModel):
    framework: str = Field(examples=["soc2", "gdpr", "hipaa", "pci_dss"])
    since: datetime | None = None   # defaults to trailing 90 days
    until: datetime | None = None


class ComplianceReportOut(BaseModel):
    framework: str
    framework_name: str
    organization: str
    org_slug: str
    period_start: str
    period_end: str
    ledger_attestation: dict[str, Any]
    coverage: dict[str, Any]
    gaps: list[str] = Field(default_factory=list)
    controls: list[dict[str, Any]] = Field(default_factory=list)
    disclaimer: str


# --- Dashboard --------------------------------------------------------------

class DashboardStats(BaseModel):
    agents_total: int
    agents_active: int
    roles_total: int
    policies_total: int
    connectors_total: int
    connectors_active: int
    decisions_total: int
    decisions_allowed: int
    decisions_denied: int
    decisions_pending_approval: int
    approvals_pending: int
    dlp_incidents: int
    alerts_open: int = 0
    ledger_valid: bool
    ledger_length: int


# Resolve forward reference.
TokenResponse.model_rebuild()
