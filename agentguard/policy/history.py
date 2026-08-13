"""Policy change history + rollback.

Records an immutable snapshot on every policy create / update / delete so an
operator can audit who changed a rule and restore any prior state. This is
change management *for the policies themselves* — distinct from the audit ledger
(which records agent decisions); here we record operator edits to the rule set.
"""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..models import Policy, PolicyVersion

# The policy fields that fully describe a rule (what a rollback restores).
_SNAPSHOT_FIELDS = ("name", "effect", "resource", "actions", "conditions",
                    "require_approval", "priority", "enabled")

_MAX_VERSION_RETRIES = 5


def snapshot(policy: Policy) -> dict:
    return {f: getattr(policy, f) for f in _SNAPSHOT_FIELDS}


def _next_version(db: Session, policy_id: int) -> int:
    current = db.scalar(
        select(func.max(PolicyVersion.version)).where(PolicyVersion.policy_id == policy_id)
    )
    return (current or 0) + 1


def record(db: Session, policy: Policy, action: str, actor: str, *,
           org_id: int | None) -> PolicyVersion:
    """Append a version snapshot for ``policy``. Caller commits.

    The version number is allocated as ``max+1``; under a concurrent edit two
    writers can pick the same number, but the UNIQUE(policy_id, version)
    constraint rejects the duplicate. The insert runs inside a SAVEPOINT so that
    on collision only the version row is rolled back (the caller's policy
    mutation in the outer transaction is preserved) and a fresh number is tried.
    """
    snap = snapshot(policy)
    last_error: IntegrityError | None = None
    for _ in range(_MAX_VERSION_RETRIES):
        version = PolicyVersion(
            org_id=org_id,
            role_id=policy.role_id,
            policy_id=policy.id,
            version=_next_version(db, policy.id),
            action=action,
            snapshot=snap,
            changed_by=actor,
        )
        try:
            with db.begin_nested():  # SAVEPOINT — rolls back only this insert
                db.add(version)
                db.flush()
            return version
        except IntegrityError as exc:  # duplicate (policy_id, version) — retry
            last_error = exc
    raise RuntimeError("could not allocate a policy version") from last_error


def apply_snapshot(policy: Policy, snap: dict) -> None:
    """Restore a policy's fields from a snapshot (used by rollback)."""
    for field in _SNAPSHOT_FIELDS:
        if field in snap:
            setattr(policy, field, snap[field])
