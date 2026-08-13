"""The agent-facing enforcement API.

Agents call ``POST /v1/gateway/authorize`` *before* performing an action. The
control plane returns ``allow`` / ``deny`` / ``require_approval`` and records the
decision in the tamper-evident ledger. Actions needing sign-off can be polled at
``GET /v1/gateway/approvals/{id}``.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ..brokers import publish_message
from ..database import get_db
from ..db_connector import execute_query, execute_write
from ..models import Agent, Approval
from ..policy.engine import ActionRequest
from ..schemas import (
    ApprovalOut,
    AuthorizeRequest,
    AuthorizeResponse,
    DLPFindingOut,
    ExecuteRequest,
    ExecuteResponse,
    PublishRequest,
    PublishResponse,
    QueryRequest,
    QueryResponse,
    WriteRequest,
    WriteResponse,
)
from ..security import get_authenticated_agent
from ..gateway_service import authorize_action, execute_action
from ..tracing import span

router = APIRouter(prefix="/v1/gateway", tags=["gateway"])


@router.post("/authorize", response_model=AuthorizeResponse)
def authorize(
    body: AuthorizeRequest,
    db: Session = Depends(get_db),
    agent: Agent = Depends(get_authenticated_agent),
) -> AuthorizeResponse:
    req = ActionRequest(
        action_type=body.action_type,
        resource=body.resource,
        payload=body.payload,
        metadata=body.metadata,
        attributes=body.attributes,
    )
    with span("gateway.authorize", **{"agentguard.agent": agent.name,
                                      "agentguard.action": body.action_type,
                                      "agentguard.resource": body.resource}):
        result = authorize_action(db, agent, req)
    d = result.decision
    return AuthorizeResponse(
        decision=d.decision,
        reason=d.reason,
        request_id=result.audit_record.id,
        approval_id=result.approval.id if result.approval else None,
        matched_policy_id=d.matched_policy_id,
        obligations=d.obligations,
        dlp_findings=[DLPFindingOut(**f) for f in (d.dlp.findings_as_dicts() if d.dlp else [])],
        risk_score=result.risk.score if result.risk else None,
        risk_factors=result.risk.factors if result.risk else [],
        audit_seq=result.audit_record.seq,
        audit_hash=result.audit_record.hash,
    )


@router.post("/execute", response_model=ExecuteResponse)
def execute(
    body: ExecuteRequest,
    db: Session = Depends(get_db),
    agent: Agent = Depends(get_authenticated_agent),
) -> ExecuteResponse:
    """Enforced mode: the plane authorizes AND performs the upstream call.

    The agent never holds the credential or base URL, so it cannot bypass the
    control plane to reach the upstream directly.
    """
    try:
        result = execute_action(
            db,
            agent,
            connector_name=body.connector,
            method=body.method,
            path=body.path,
            headers=body.headers,
            body=body.body,
            metadata=body.metadata,
            approval_id=body.approval_id,
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))

    d = result.decision
    req_findings = d.dlp.findings_as_dicts() if d.dlp else []
    return ExecuteResponse(
        executed=result.executed,
        decision=d.decision,
        reason=d.reason,
        request_id=result.audit_record.id,
        approval_id=result.approval.id if result.approval else None,
        status_code=result.status_code,
        response_headers=result.response_headers,
        response_body=result.response_body,
        response_dlp_findings=[DLPFindingOut(**f) for f in result.response_dlp_findings],
        request_dlp_findings=[DLPFindingOut(**f) for f in req_findings],
        upstream_error=result.upstream_error,
        audit_seq=result.audit_record.seq,
        audit_hash=result.audit_record.hash,
    )


@router.post("/query", response_model=QueryResponse)
def query(
    body: QueryRequest,
    db: Session = Depends(get_db),
    agent: Agent = Depends(get_authenticated_agent),
) -> QueryResponse:
    """Enforced read-only SQL: the plane holds the DSN and runs the query.

    Only ``SELECT`` / ``WITH`` are permitted; results are row-capped and
    DLP-redacted before they reach the agent.
    """
    try:
        result = execute_query(
            db,
            agent,
            connector_name=body.connector,
            sql=body.sql,
            params=body.params,
            metadata=body.metadata,
            approval_id=body.approval_id,
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))

    return QueryResponse(
        executed=result.executed,
        decision=result.decision.decision,
        reason=result.decision.reason,
        request_id=result.audit_record.id,
        approval_id=result.approval.id if result.approval else None,
        columns=result.columns,
        rows=result.rows,
        row_count=result.row_count,
        response_dlp_findings=[DLPFindingOut(**f) for f in result.response_dlp_findings],
        error=result.error,
        audit_seq=result.audit_record.seq,
        audit_hash=result.audit_record.hash,
    )


@router.post("/write", response_model=WriteResponse)
def write(
    body: WriteRequest,
    db: Session = Depends(get_db),
    agent: Agent = Depends(get_authenticated_agent),
) -> WriteResponse:
    """Governed write (INSERT/UPDATE/DELETE) against a *writable* DB connector.

    Runs in a transaction and rolls back if the connector's row-affected cap is
    exceeded; only DML is permitted (never DDL).
    """
    try:
        result = execute_write(
            db,
            agent,
            connector_name=body.connector,
            sql=body.sql,
            params=body.params,
            metadata=body.metadata,
            approval_id=body.approval_id,
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))

    return WriteResponse(
        executed=result.executed,
        decision=result.decision.decision,
        reason=result.decision.reason,
        request_id=result.audit_record.id,
        approval_id=result.approval.id if result.approval else None,
        rows_affected=result.row_count,
        error=result.error,
        audit_seq=result.audit_record.seq,
        audit_hash=result.audit_record.hash,
    )


@router.post("/publish", response_model=PublishResponse)
def publish(
    body: PublishRequest,
    db: Session = Depends(get_db),
    agent: Agent = Depends(get_authenticated_agent),
) -> PublishResponse:
    """Governed message-broker publish: policy + DLP + ledger before it hits the topic."""
    try:
        with span("gateway.publish", **{"agentguard.agent": agent.name,
                                        "agentguard.topic": body.topic}):
            result = publish_message(
                db, agent,
                connector_name=body.connector, topic=body.topic, message=body.message,
                key=body.key, metadata=body.metadata, approval_id=body.approval_id,
            )
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))

    return PublishResponse(
        executed=result.executed,
        decision=result.decision.decision,
        reason=result.decision.reason,
        request_id=result.audit_record.id,
        approval_id=result.approval.id if result.approval else None,
        request_dlp_findings=[DLPFindingOut(**f) for f in result.request_dlp_findings],
        error=result.error,
        audit_seq=result.audit_record.seq,
        audit_hash=result.audit_record.hash,
    )


@router.get("/approvals/{approval_id}", response_model=ApprovalOut)
def poll_approval(
    approval_id: int,
    db: Session = Depends(get_db),
    agent: Agent = Depends(get_authenticated_agent),
) -> Approval:
    approval = db.get(Approval, approval_id)
    if not approval or approval.agent_id != agent.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Approval not found")
    from ..approvals_service import expire_if_stale

    return expire_if_stale(db, approval)


@router.get("/whoami")
def whoami(agent: Agent = Depends(get_authenticated_agent)) -> dict:
    return {
        "agent_id": agent.id,
        "name": agent.name,
        "role": agent.role.name if agent.role else None,
        "status": agent.status,
        "quota": agent.quota,
    }
