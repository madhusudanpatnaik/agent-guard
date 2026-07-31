"""Human-in-the-loop approval queue (operator side)."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..approvals_service import expire_if_stale, sweep_expired
from ..audit.ledger import AuditLedger
from ..database import get_db
from ..models import Approval, ApprovalStatus, Decision, User
from ..schemas import ApprovalDecision, ApprovalOut
from ..security import require_admin
from ..tenancy import owned_or_404, scope

router = APIRouter(prefix="/approvals", tags=["approvals"])


@router.get("", response_model=list[ApprovalOut])
def list_approvals(
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
    status_filter: str | None = None,
    limit: int = Query(default=100, le=1000),
    offset: int = Query(default=0, ge=0),
) -> list[Approval]:
    sweep_expired(db)  # keep the queue truthful without a background worker
    stmt = scope(select(Approval), Approval, user).order_by(Approval.created_at.desc())
    if status_filter:
        stmt = stmt.where(Approval.status == status_filter)
    return list(db.scalars(stmt.offset(offset).limit(limit)))


@router.post("/{approval_id}/resolve", response_model=ApprovalOut)
def resolve(
    approval_id: int,
    body: ApprovalDecision,
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
) -> Approval:
    approval = owned_or_404(db.get(Approval, approval_id), user, "Approval")
    expire_if_stale(db, approval)
    if approval.status != ApprovalStatus.PENDING:
        raise HTTPException(
            status.HTTP_409_CONFLICT, f"Approval already {approval.status}"
        )

    approval.status = ApprovalStatus.APPROVED if body.approve else ApprovalStatus.DENIED
    approval.resolved_by = user.email
    approval.resolution_note = body.note
    approval.resolved_at = datetime.now(timezone.utc)

    # Record the human decision as its own immutable ledger entry.
    AuditLedger(db).append(
        agent_id=approval.agent_id,
        agent_name=approval.agent_name,
        role_name="",
        action_type=f"approval.{'approved' if body.approve else 'denied'}",
        resource=approval.resource,
        decision=Decision.ALLOW if body.approve else Decision.DENY,
        reason=f"Approval #{approval.id} {approval.status} by {user.email}. {body.note}".strip(),
        billable=False,  # a human decision must not consume the agent's quota
        org_id=approval.org_id,
    )
    db.commit()
    db.refresh(approval)
    return approval
