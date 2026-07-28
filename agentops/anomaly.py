"""Behavioral baselines & anomaly detection over the audit ledger.

Enforcement decides *whether* an action is permitted; anomaly detection asks a
different question — *is this normal for this agent?* An agent that suddenly
touches a resource it has never used, runs at 3am when it has only ever run in
business hours, or does 50× its usual volume is worth flagging even when each
individual action is within policy.

These are cheap, index-backed queries over the append-only ledger (no separate
feature store): the ledger already records every governed action, so an agent's
own history *is* its baseline. Signals are consumed by :mod:`agentops.risk` to
compute a per-decision risk score and, optionally, by the alerting layer.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .models import AuditRecord, Decision


def has_seen_resource(db: Session, agent_id: int, resource: str) -> bool:
    """True if this agent has acted on ``resource`` before (novelty check)."""
    hit = db.scalar(
        select(AuditRecord.id).where(
            AuditRecord.agent_id == agent_id,
            AuditRecord.resource == resource,
            AuditRecord.billable.is_(True),
        ).limit(1)
    )
    return hit is not None


def has_seen_action(db: Session, agent_id: int, action_type: str) -> bool:
    """True if this agent has performed ``action_type`` before."""
    hit = db.scalar(
        select(AuditRecord.id).where(
            AuditRecord.agent_id == agent_id,
            AuditRecord.action_type == action_type,
            AuditRecord.billable.is_(True),
        ).limit(1)
    )
    return hit is not None


def is_off_hours(now: datetime, *, start_hour: int = 6, end_hour: int = 22) -> bool:
    """True if ``now`` (UTC) falls outside the agent's typical active window."""
    return not (start_hour <= now.hour < end_hour)


def recent_denial_ratio(db: Session, agent_id: int, seconds: int = 300) -> float:
    """Fraction of this agent's recent actions that were denied (0.0–1.0)."""
    since = datetime.now(timezone.utc) - timedelta(seconds=seconds)
    total = db.scalar(
        select(func.count(AuditRecord.id)).where(
            AuditRecord.agent_id == agent_id,
            AuditRecord.created_at >= since,
            AuditRecord.billable.is_(True),
        )
    ) or 0
    if total == 0:
        return 0.0
    denied = db.scalar(
        select(func.count(AuditRecord.id)).where(
            AuditRecord.agent_id == agent_id,
            AuditRecord.created_at >= since,
            AuditRecord.billable.is_(True),
            AuditRecord.decision == Decision.DENY,
        )
    ) or 0
    return denied / total


def volume_zscore(db: Session, agent_id: int, *, window_seconds: int = 300,
                  lookback_windows: int = 12) -> float:
    """Standard-score of the current window's volume vs. the agent's baseline.

    Compares the count of billable actions in the trailing ``window_seconds`` to
    the mean/stdev of the preceding ``lookback_windows`` windows. A high positive
    z-score means a volume surge relative to this agent's own recent norm.
    Returns 0.0 until there is enough history to be meaningful.

    A single query fetches the timestamps once and buckets them in Python — one
    round-trip instead of one COUNT per window — so this stays cheap on the hot
    authorization path.
    """
    now = datetime.now(timezone.utc)
    total_span = window_seconds * (lookback_windows + 1)
    since = now - timedelta(seconds=total_span)
    buckets = [0] * (lookback_windows + 1)
    for ts in db.scalars(
        select(AuditRecord.created_at).where(
            AuditRecord.agent_id == agent_id,
            AuditRecord.created_at >= since,
            AuditRecord.billable.is_(True),
        )
    ):
        if ts is None:
            continue
        if ts.tzinfo is None:  # SQLite returns naive UTC
            ts = ts.replace(tzinfo=timezone.utc)
        idx = int((now - ts).total_seconds() // window_seconds)
        if 0 <= idx <= lookback_windows:
            buckets[idx] += 1  # bucket 0 = current window, 1..N = history
    current, history = buckets[0], buckets[1:]
    if len([h for h in history if h > 0]) < 3:
        return 0.0  # not enough baseline yet
    mean = sum(history) / len(history)
    var = sum((h - mean) ** 2 for h in history) / len(history)
    stdev = var ** 0.5
    if stdev == 0:
        return 0.0 if current <= mean else 3.0  # any spike off a flat baseline
    return (current - mean) / stdev
