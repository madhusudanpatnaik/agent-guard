"""Organization (tenant) management — platform-superadmin only.

A superadmin provisions organizations and their first users. Everything else in
the API is scoped to the caller's own organization, so an org's own admins never
see other tenants.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..audit.ledger import AuditLedger
from ..database import get_db
from ..models import Decision, Organization, User
from ..schemas import ContainmentRequest, OrgIn, OrgOut, OrgUserIn, UserOut
from ..security import hash_password, require_admin, require_superadmin

router = APIRouter(prefix="/orgs", tags=["orgs"])


@router.get("", response_model=list[OrgOut])
def list_orgs(db: Session = Depends(get_db), _: User = Depends(require_superadmin)):
    return list(db.scalars(select(Organization).order_by(Organization.name)))


@router.post("", response_model=OrgOut, status_code=status.HTTP_201_CREATED)
def create_org(
    body: OrgIn, db: Session = Depends(get_db), _: User = Depends(require_superadmin)
) -> Organization:
    if db.scalar(select(Organization).where(
        (Organization.slug == body.slug) | (Organization.name == body.name)
    )):
        raise HTTPException(status.HTTP_409_CONFLICT, "Organization name or slug already exists")
    org = Organization(name=body.name, slug=body.slug)
    db.add(org)
    db.commit()
    db.refresh(org)
    return org


@router.post("/containment", response_model=OrgOut)
def set_own_containment(
    body: ContainmentRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
) -> Organization:
    """Emergency kill switch for the caller's own org — freeze or resume the fleet.

    When contained, every agent action in the org is denied at the gateway until
    an operator resumes. The toggle itself is recorded in the audit ledger.
    """
    org = db.get(Organization, user.org_id)
    if org is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
    _apply_containment(db, org, body, user.email)
    return org


@router.post("/{org_id}/containment", response_model=OrgOut)
def set_org_containment(
    org_id: int,
    body: ContainmentRequest,
    db: Session = Depends(get_db),
    _: User = Depends(require_superadmin),
) -> Organization:
    """Superadmin kill switch for any org (cross-tenant incident response)."""
    org = db.get(Organization, org_id)
    if org is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
    _apply_containment(db, org, body, "superadmin")
    return org


def _apply_containment(db: Session, org: Organization, body: ContainmentRequest,
                       actor: str) -> None:
    now = datetime.now(timezone.utc)
    org.contained = body.contained
    org.contained_reason = body.reason if body.contained else ""
    org.contained_at = now if body.contained else None
    org.contained_by = actor if body.contained else ""
    until = (now + timedelta(minutes=body.duration_minutes)
             if body.contained and body.duration_minutes else None)
    org.contained_until = until
    window = f" for {body.duration_minutes}m (until {until.isoformat()})" if until else ""
    # Record the fleet-level control action in the tamper-evident ledger.
    AuditLedger(db).append(
        agent_id=None, agent_name="", role_name="",
        action_type="org.contain" if body.contained else "org.resume",
        resource=f"org:{org.slug}",
        decision=Decision.DENY if body.contained else Decision.ALLOW,
        reason=(f"Org contained by {actor}: {body.reason}{window}" if body.contained
                else f"Org containment lifted by {actor}"),
        billable=False, org_id=org.id,
    )
    db.commit()
    db.refresh(org)


@router.post("/{org_id}/users", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_org_user(
    org_id: int,
    body: OrgUserIn,
    db: Session = Depends(get_db),
    _: User = Depends(require_superadmin),
) -> User:
    org = db.get(Organization, org_id)
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
    email = body.email.lower().strip()
    if db.scalar(select(User).where(User.email == email)):
        raise HTTPException(status.HTTP_409_CONFLICT, "A user with that email already exists")
    user = User(
        org_id=org.id,
        email=email,
        password_hash=hash_password(body.password),
        role=body.role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user
