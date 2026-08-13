"""Agent registry — scoped to the caller's org."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..database import get_db
from ..models import Agent, AgentStatus, Role, User
from ..reputation import compute as compute_reputation
from ..schemas import (
    AgentCreated,
    AgentIn,
    AgentOut,
    AgentStatusUpdate,
    AgentUpdate,
    ReputationOut,
)
from ..security import generate_api_key, require_admin
from ..tenancy import owned_or_404, same_org, scope

router = APIRouter(prefix="/agents", tags=["agents"])


def _agent_in_org(db: Session, agent_id: int, user: User) -> Agent:
    return owned_or_404(db.get(Agent, agent_id), user, "Agent")


def _require_role_in_org(db: Session, role_id: int, user: User) -> Role:
    role = db.get(Role, role_id)
    if role is None or not same_org(role, user):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "role_id does not exist")
    return role


@router.get("", response_model=list[AgentOut])
def list_agents(
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
    limit: int = Query(default=100, le=1000),
    offset: int = Query(default=0, ge=0),
    status_filter: str | None = Query(default=None, alias="status"),
    role_id: int | None = None,
) -> list[Agent]:
    stmt = scope(select(Agent), Agent, user).order_by(Agent.created_at.desc())
    if status_filter:
        stmt = stmt.where(Agent.status == status_filter)
    if role_id is not None:
        stmt = stmt.where(Agent.role_id == role_id)
    return list(db.scalars(stmt.offset(offset).limit(limit)))


@router.post("", response_model=AgentCreated, status_code=status.HTTP_201_CREATED)
def register_agent(
    body: AgentIn, db: Session = Depends(get_db), user: User = Depends(require_admin)
) -> AgentCreated:
    _require_role_in_org(db, body.role_id, user)
    plaintext, key_hash, prefix = generate_api_key()
    agent = Agent(
        name=body.name,
        description=body.description,
        role_id=body.role_id,
        org_id=user.org_id,
        owner=body.owner,
        quota=body.quota or get_settings().default_agent_quota,
        api_key_hash=key_hash,
        api_key_prefix=prefix,
        status=AgentStatus.ACTIVE,
    )
    db.add(agent)
    db.commit()
    db.refresh(agent)
    return AgentCreated(**AgentOut.model_validate(agent).model_dump(), api_key=plaintext)


@router.get("/{agent_id}", response_model=AgentOut)
def get_agent(agent_id: int, db: Session = Depends(get_db), user: User = Depends(require_admin)) -> Agent:
    return _agent_in_org(db, agent_id, user)


@router.get("/{agent_id}/reputation", response_model=ReputationOut)
def get_reputation(agent_id: int, db: Session = Depends(get_db),
                   user: User = Depends(require_admin)) -> ReputationOut:
    """Rolling 0–100 trust score for this agent from its ledger + alert history."""
    agent = _agent_in_org(db, agent_id, user)
    return ReputationOut(**compute_reputation(db, agent).as_dict())


@router.put("/{agent_id}", response_model=AgentOut)
def update_agent(
    agent_id: int,
    body: AgentUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
) -> Agent:
    agent = _agent_in_org(db, agent_id, user)
    if body.name is not None:
        agent.name = body.name
    if body.description is not None:
        agent.description = body.description
    if body.role_id is not None:
        _require_role_in_org(db, body.role_id, user)
        agent.role_id = body.role_id
    if body.owner is not None:
        agent.owner = body.owner
    if body.quota is not None:
        agent.quota = body.quota
    db.commit()
    db.refresh(agent)
    return agent


@router.post("/{agent_id}/status", response_model=AgentOut)
def set_status(
    agent_id: int,
    body: AgentStatusUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
) -> Agent:
    agent = _agent_in_org(db, agent_id, user)
    agent.status = body.status
    db.commit()
    db.refresh(agent)
    return agent


@router.post("/{agent_id}/rotate-key", response_model=AgentCreated)
def rotate_key(
    agent_id: int, db: Session = Depends(get_db), user: User = Depends(require_admin)
) -> AgentCreated:
    agent = _agent_in_org(db, agent_id, user)
    plaintext, key_hash, prefix = generate_api_key()
    agent.api_key_hash = key_hash
    agent.api_key_prefix = prefix
    db.commit()
    db.refresh(agent)
    return AgentCreated(**AgentOut.model_validate(agent).model_dump(), api_key=plaintext)


@router.delete("/{agent_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_agent(
    agent_id: int, db: Session = Depends(get_db), user: User = Depends(require_admin)
) -> None:
    agent = _agent_in_org(db, agent_id, user)
    db.delete(agent)
    db.commit()
