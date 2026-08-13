"""Org containment (kill switch) state — with time-bound auto-expiry.

Containment freezes every agent action in an org. An optional ``contained_until``
makes the freeze self-lifting so an incident-response freeze can't be forgotten.
This module is the single source of truth for "is this org currently frozen?" —
it lazily auto-resumes an expired freeze (recording the auto-resume in the
ledger) so both the gateway hot path and the background sweeper agree.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from .audit.ledger import AuditLedger
from .models import Decision, Organization


def _aware(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


def _auto_resume(db: Session, org: Organization) -> None:
    """Lift an expired freeze and record it, attributed to the system.

    Uses a compare-and-swap (``UPDATE ... WHERE contained IS TRUE``) so that when
    two concurrent requests both observe the same expired freeze, exactly one
    wins the update (rowcount == 1) and writes the single ``org.resume`` ledger
    entry — the loser matches 0 rows and skips the append, avoiding a duplicate
    audit record (and duplicate SIEM/anchor side-effects) for one expiry event.
    """
    result = db.execute(
        update(Organization)
        .where(Organization.id == org.id, Organization.contained.is_(True))
        .values(contained=False, contained_reason="", contained_at=None,
                contained_by="", contained_until=None)
    )
    db.commit()
    db.refresh(org)
    if (getattr(result, "rowcount", 0) or 0) == 0:
        return  # another request already lifted it — no duplicate ledger row
    AuditLedger(db).append(
        agent_id=None, agent_name="", role_name="",
        action_type="org.resume", resource=f"org:{org.slug}",
        decision=Decision.ALLOW,
        reason="Org containment auto-lifted (time-bound window elapsed).",
        billable=False, org_id=org.id,
    )
    db.commit()


def active(db: Session, org: Organization | None, *, now: datetime | None = None) -> bool:
    """True if ``org`` is contained right now; auto-resumes an expired freeze."""
    if org is None or not org.contained:
        return False
    now = now or datetime.now(timezone.utc)
    until = _aware(org.contained_until)
    if until is not None and now >= until:
        _auto_resume(db, org)
        return False
    return True


def sweep_expired(db: Session) -> int:
    """Auto-resume every org whose containment window has elapsed. Returns count."""
    now = datetime.now(timezone.utc)
    contained = db.scalars(select(Organization).where(Organization.contained.is_(True)))
    count = 0
    for org in contained:
        until = _aware(org.contained_until)
        if until is not None and now >= until:
            _auto_resume(db, org)
            count += 1
    return count
