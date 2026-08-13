"""Role and policy management (the RBAC catalog) — scoped to the caller's org."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Policy, PolicyVersion, Role, User
from ..policy import history
from ..policy.analyzer import analyze_role, preview_policy, recommend_policies
from ..schemas import (
    ApplyRecommendationRequest,
    PolicyAnalysisOut,
    PolicyImpactOut,
    PolicyIn,
    PolicyOut,
    PolicyPreviewRequest,
    PolicyRecommendationOut,
    PolicyVersionOut,
    RoleIn,
    RoleOut,
    RoleUpdate,
)
from ..security import require_admin
from ..tenancy import owned_or_404, scope

router = APIRouter(prefix="/roles", tags=["roles"])


def _role_in_org(db: Session, role_id: int, user: User) -> Role:
    return owned_or_404(db.get(Role, role_id), user, "Role")


@router.get("", response_model=list[RoleOut])
def list_roles(
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
    limit: int = Query(default=100, le=1000),
    offset: int = Query(default=0, ge=0),
) -> list[Role]:
    stmt = scope(select(Role), Role, user).order_by(Role.name).offset(offset).limit(limit)
    return list(db.scalars(stmt))


@router.post("", response_model=RoleOut, status_code=status.HTTP_201_CREATED)
def create_role(
    body: RoleIn, db: Session = Depends(get_db), user: User = Depends(require_admin)
) -> Role:
    exists = db.scalar(
        scope(select(Role), Role, user).where(Role.name == body.name)
    )
    if exists:
        raise HTTPException(status.HTTP_409_CONFLICT, "Role name already exists")
    role = Role(name=body.name, description=body.description, org_id=user.org_id)
    db.add(role)
    db.commit()
    db.refresh(role)
    return role


@router.get("/{role_id}", response_model=RoleOut)
def get_role(role_id: int, db: Session = Depends(get_db), user: User = Depends(require_admin)) -> Role:
    return _role_in_org(db, role_id, user)


@router.get("/{role_id}/analysis", response_model=PolicyAnalysisOut)
def analyze(role_id: int, db: Session = Depends(get_db),
            user: User = Depends(require_admin)) -> PolicyAnalysisOut:
    """Policy intelligence: shadowed / redundant / broad / unused rules + denial hotspots."""
    role = _role_in_org(db, role_id, user)
    return PolicyAnalysisOut(**analyze_role(db, role).as_dict())


@router.get("/{role_id}/recommendations", response_model=list[PolicyRecommendationOut])
def recommendations(role_id: int, db: Session = Depends(get_db),
                    user: User = Depends(require_admin)) -> list[PolicyRecommendationOut]:
    """Candidate allow policies generated from recurring default-deny gaps."""
    role = _role_in_org(db, role_id, user)
    return [PolicyRecommendationOut(**r.as_dict()) for r in recommend_policies(db, role)]


@router.post("/{role_id}/policies/preview", response_model=PolicyImpactOut)
def preview(role_id: int, body: PolicyPreviewRequest, db: Session = Depends(get_db),
            user: User = Depends(require_admin)) -> PolicyImpactOut:
    """Dry-run a candidate allow policy against this role's real denied traffic.

    Shows how many previously-denied actions it would newly permit and flags any
    that carried DLP findings — the blast radius, before you adopt the rule.
    """
    role = _role_in_org(db, role_id, user)
    return PolicyImpactOut(**preview_policy(db, role, body.resource, body.actions).as_dict())


@router.post("/{role_id}/recommendations/apply", response_model=PolicyOut,
             status_code=status.HTTP_201_CREATED)
def apply_recommendation(
    role_id: int,
    body: ApplyRecommendationRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
) -> Policy:
    """One-click adopt a recommended policy (creates an allow rule on the role)."""
    _role_in_org(db, role_id, user)
    policy = Policy(
        role_id=role_id, effect="allow", resource=body.resource,
        actions=body.actions or ["*"], require_approval=body.require_approval,
        name=body.name or f"auto: {body.resource}",
    )
    db.add(policy)
    db.commit()
    db.refresh(policy)
    return policy


@router.put("/{role_id}", response_model=RoleOut)
def update_role(
    role_id: int,
    body: RoleUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
) -> Role:
    role = _role_in_org(db, role_id, user)
    if body.name is not None:
        clash = db.scalar(
            scope(select(Role), Role, user).where(Role.name == body.name, Role.id != role_id)
        )
        if clash:
            raise HTTPException(status.HTTP_409_CONFLICT, "Role name already exists")
        role.name = body.name
    if body.description is not None:
        role.description = body.description
    db.commit()
    db.refresh(role)
    return role


@router.delete("/{role_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_role(
    role_id: int, db: Session = Depends(get_db), user: User = Depends(require_admin)
) -> None:
    role = _role_in_org(db, role_id, user)
    if role.agents:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Role still bound to {len(role.agents)} agent(s); reassign them first.",
        )
    db.delete(role)
    db.commit()


# --- Policies (nested under a role) -----------------------------------------

@router.post("/{role_id}/policies", response_model=PolicyOut, status_code=status.HTTP_201_CREATED)
def add_policy(
    role_id: int,
    body: PolicyIn,
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
) -> Policy:
    _role_in_org(db, role_id, user)
    policy = Policy(role_id=role_id, **body.model_dump())
    db.add(policy)
    # flush (not commit) so the policy gets an id for the snapshot, and the rule
    # change + its history version land in ONE transaction (no partial state
    # where an enforced policy has no version snapshot).
    db.flush()
    history.record(db, policy, "create", user.email, org_id=user.org_id)
    db.commit()
    db.refresh(policy)
    return policy


@router.put("/{role_id}/policies/{policy_id}", response_model=PolicyOut)
def update_policy(
    role_id: int,
    policy_id: int,
    body: PolicyIn,
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
) -> Policy:
    _role_in_org(db, role_id, user)
    policy = db.get(Policy, policy_id)
    if not policy or policy.role_id != role_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Policy not found for this role")
    for key, value in body.model_dump().items():
        setattr(policy, key, value)
    # Mutation + history snapshot in a single transaction (atomic).
    history.record(db, policy, "update", user.email, org_id=user.org_id)
    db.commit()
    db.refresh(policy)
    return policy


@router.delete("/{role_id}/policies/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_policy(
    role_id: int,
    policy_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
) -> None:
    _role_in_org(db, role_id, user)
    policy = db.get(Policy, policy_id)
    if not policy or policy.role_id != role_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Policy not found for this role")
    # Snapshot the final state before deletion so the history (and a future
    # rollback) survives the row being removed.
    history.record(db, policy, "delete", user.email, org_id=user.org_id)
    db.delete(policy)
    db.commit()


@router.get("/{role_id}/policies/{policy_id}/versions", response_model=list[PolicyVersionOut])
def policy_versions(
    role_id: int, policy_id: int, db: Session = Depends(get_db),
    user: User = Depends(require_admin),
) -> list[PolicyVersion]:
    """Change history for a policy (newest first), org-scoped."""
    _role_in_org(db, role_id, user)
    stmt = scope(select(PolicyVersion), PolicyVersion, user).where(
        PolicyVersion.policy_id == policy_id).order_by(PolicyVersion.version.desc())
    return list(db.scalars(stmt))


@router.post("/{role_id}/policies/{policy_id}/rollback/{version}", response_model=PolicyOut)
def rollback_policy(
    role_id: int, policy_id: int, version: int,
    db: Session = Depends(get_db), user: User = Depends(require_admin),
) -> Policy:
    """Restore a policy to a prior version's snapshot (recorded as a new version)."""
    _role_in_org(db, role_id, user)
    policy = db.get(Policy, policy_id)
    if not policy or policy.role_id != role_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Policy not found for this role")
    target = db.scalar(
        scope(select(PolicyVersion), PolicyVersion, user).where(
            PolicyVersion.policy_id == policy_id, PolicyVersion.version == version)
    )
    if not target:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Version not found")
    history.apply_snapshot(policy, target.snapshot)
    # Restore + new "rollback" version snapshot in a single transaction.
    history.record(db, policy, "rollback", user.email, org_id=user.org_id)
    db.commit()
    db.refresh(policy)
    return policy
