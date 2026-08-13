"""Policy simulator — dry-run a decision without executing or logging it.

"Shift-left" governance: test what the plane *would* decide for a given action,
either against a role's live policies or against an ad-hoc "what-if" policy set,
before you deploy a change. Nothing is executed and nothing is written to the
ledger — it is a pure evaluation of the policy engine.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ..config import get_settings
from ..database import get_db
from ..dlp.scanner import scan_payload
from ..models import Agent, Policy, Role, User
from ..policy.engine import ActionRequest, PolicyEngine
from ..schemas import DLPFindingOut, SimulateRequest, SimulateResponse
from ..security import require_admin
from ..tenancy import same_org

router = APIRouter(prefix="/policy", tags=["policy"])


@router.post("/simulate", response_model=SimulateResponse)
def simulate(
    body: SimulateRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
) -> SimulateResponse:
    settings = get_settings()

    if body.policies is not None:
        # Ad-hoc "what-if": transient, unsaved policies with synthetic ids.
        policies = [
            Policy(
                id=-(i + 1), role_id=0, name=p.name, effect=p.effect, resource=p.resource,
                actions=p.actions, conditions=p.conditions,
                require_approval=p.require_approval, priority=p.priority, enabled=p.enabled,
            )
            for i, p in enumerate(body.policies)
        ]
    else:
        role: Role | None = None
        if body.role_id is not None:
            candidate = db.get(Role, body.role_id)
            role = candidate if same_org(candidate, user) else None
        elif body.agent_id is not None:
            agent = db.get(Agent, body.agent_id)
            if same_org(agent, user) and agent is not None:
                role = agent.role
        if role is None:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                "Provide one of: role_id, agent_id (in your org), or an ad-hoc policies list.",
            )
        policies = list(role.policies)

    req = ActionRequest(
        action_type=body.action_type, resource=body.resource,
        payload=body.payload, metadata=body.metadata,
        attributes=body.attributes,
    )
    dlp = scan_payload(body.payload)
    engine = PolicyEngine(
        default_deny=settings.default_deny,
        block_egress_on_secret=settings.dlp_block_egress_on_secret,
    )
    # rate_counter is intentionally omitted — rate limits depend on live traffic
    # and are not part of a static dry-run.
    decision = engine.evaluate(req, policies, dlp=dlp)

    return SimulateResponse(
        decision=decision.decision,
        reason=decision.reason,
        matched_policy_id=decision.matched_policy_id,
        obligations=decision.obligations,
        dlp_findings=[DLPFindingOut(**f) for f in (dlp.findings_as_dicts() if dlp else [])],
        is_egress=req.is_egress(),
        evaluated_policies=len(policies),
    )
