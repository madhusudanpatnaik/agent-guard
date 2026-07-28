"""Aggregate metrics for the operator console — scoped to the caller's org."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from fastapi.responses import PlainTextResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..audit.ledger import chain_status
from ..database import get_db
from ..models import (
    Agent,
    AgentStatus,
    Alert,
    AlertStatus,
    Approval,
    ApprovalStatus,
    AuditRecord,
    Connector,
    Decision,
    Policy,
    Role,
    User,
)
from ..schemas import DashboardStats
from ..security import get_current_user

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


def _count(db: Session, model, *where) -> int:
    stmt = select(func.count()).select_from(model)
    for clause in where:
        stmt = stmt.where(clause)
    return db.scalar(stmt) or 0


def _build_stats(db: Session, user: User) -> DashboardStats:
    org = user.org_id
    # Integrity is a global platform property. Uses the verified-prefix cache
    # (incremental, O(new rows)) — the authoritative full walk stays on
    # /api/audit/verify and the periodic background re-verify.
    chain = chain_status(db)
    policies = db.scalar(
        select(func.count(Policy.id)).join(Role, Policy.role_id == Role.id)
        .where(Role.org_id == org)
    ) or 0
    return DashboardStats(
        agents_total=_count(db, Agent, Agent.org_id == org),
        agents_active=_count(db, Agent, Agent.org_id == org, Agent.status == AgentStatus.ACTIVE),
        roles_total=_count(db, Role, Role.org_id == org),
        policies_total=policies,
        connectors_total=_count(db, Connector, Connector.org_id == org),
        connectors_active=_count(db, Connector, Connector.org_id == org,
                                 Connector.enabled.is_(True)),
        decisions_total=_count(db, AuditRecord, AuditRecord.org_id == org),
        decisions_allowed=_count(db, AuditRecord, AuditRecord.org_id == org,
                                 AuditRecord.decision == Decision.ALLOW),
        decisions_denied=_count(db, AuditRecord, AuditRecord.org_id == org,
                                AuditRecord.decision == Decision.DENY),
        decisions_pending_approval=_count(db, AuditRecord, AuditRecord.org_id == org,
                                          AuditRecord.decision == Decision.REQUIRE_APPROVAL),
        approvals_pending=_count(db, Approval, Approval.org_id == org,
                                 Approval.status == ApprovalStatus.PENDING),
        dlp_incidents=_count(db, AuditRecord, AuditRecord.org_id == org,
                             AuditRecord.dlp_count > 0),
        alerts_open=_count(db, Alert, Alert.org_id == org, Alert.status == AlertStatus.OPEN),
        ledger_valid=chain.valid,
        ledger_length=_count(db, AuditRecord, AuditRecord.org_id == org),
    )


@router.get("/stats", response_model=DashboardStats)
def stats(db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> DashboardStats:
    return _build_stats(db, user)


@router.get("/metrics", response_class=PlainTextResponse)
def prometheus_metrics(
    db: Session = Depends(get_db), user: User = Depends(get_current_user)
) -> str:
    """Prometheus-format metrics for the caller's organization."""
    s = _build_stats(db, user)
    metrics = [
        ("agentops_agents_total", "Total registered agents", "gauge", s.agents_total),
        ("agentops_agents_active", "Currently active agents", "gauge", s.agents_active),
        ("agentops_roles_total", "Total roles defined", "gauge", s.roles_total),
        ("agentops_policies_total", "Total policies defined", "gauge", s.policies_total),
        ("agentops_connectors_total", "Total connectors registered", "gauge", s.connectors_total),
        ("agentops_connectors_active", "Enabled connectors", "gauge", s.connectors_active),
        ("agentops_decisions_total", "Total governance decisions", "counter", s.decisions_total),
        ("agentops_decisions_allowed", "Decisions allowed", "counter", s.decisions_allowed),
        ("agentops_decisions_denied", "Decisions denied", "counter", s.decisions_denied),
        ("agentops_approvals_pending", "Approvals awaiting a human", "gauge", s.approvals_pending),
        ("agentops_dlp_incidents", "Actions with DLP findings", "counter", s.dlp_incidents),
        ("agentops_ledger_valid", "Ledger integrity (1=intact)", "gauge",
         1 if s.ledger_valid else 0),
        ("agentops_ledger_length", "Audit records for this org", "gauge", s.ledger_length),
    ]
    lines: list[str] = []
    for name, help_text, kind, value in metrics:
        lines.append(f"# HELP {name} {help_text}")
        lines.append(f"# TYPE {name} {kind}")
        lines.append(f"{name} {value}")
    lines.append("")
    return "\n".join(lines)
