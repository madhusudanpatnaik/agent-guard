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

**Hot-path cost.** The individual helpers below are convenient but each costs a
round-trip; computing a full risk score with them took *five* queries per
authorization. :func:`profile` is the hot-path entry point: it fetches one
bounded window of recent rows **once** and derives every signal from it in
Python. The per-signal helpers remain for tests, ad-hoc analysis, and the exact
(unbounded) novelty check.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .config import get_settings
from .models import AuditRecord, Decision
from .utils import resource_family


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


# --------------------------------------------------------------------------- #
# Consolidated hot-path profile — ONE query feeds every behavioral signal
# --------------------------------------------------------------------------- #

# A perfectly flat baseline has zero variance, so a plain z-score is undefined
# (division by zero). Treating *any* increase as a surge is wrong: an agent that
# steadily does 1 action per window would score a full surge on its second one.
# A flat baseline is only a surge if the jump is both proportionally large and
# absolutely meaningful.
_FLAT_SURGE_MULTIPLE = 3.0   # >= 3x the flat baseline …
_FLAT_SURGE_ABSOLUTE = 5     # … and at least this many actions above it
_FLAT_SURGE_SCORE = 3.0


def _zscore_from_buckets(buckets: list[int]) -> float:
    current, history = buckets[0], buckets[1:]
    if len([h for h in history if h > 0]) < 3:
        return 0.0  # not enough baseline to say anything (incl. idle/batch agents)
    mean = sum(history) / len(history)
    stdev = (sum((h - mean) ** 2 for h in history) / len(history)) ** 0.5
    if stdev == 0:
        if (current >= mean * _FLAT_SURGE_MULTIPLE
                and current - mean >= _FLAT_SURGE_ABSOLUTE):
            return _FLAT_SURGE_SCORE
        return 0.0
    return (current - mean) / stdev


@dataclass
class BehaviorProfile:
    """All behavioral signals for one agent, derived from a single window fetch."""

    resource_seen: bool = False    # this exact resource string was seen
    family_seen: bool = False      # a resource in the same family was seen
    action_seen: bool = False
    denial_ratio: float = 0.0
    volume_z: float = 0.0
    sample_size: int = 0
    loop_repeats: int = 0          # same (action, resource) repeated back-to-back
    exact_novelty: bool = False    # True when novelty came from an exact history check
    factors: list[str] = field(default_factory=list)


def profile(db: Session, agent_id: int, resource: str, action_type: str, *,
            window_seconds: int = 300, lookback_windows: int = 12,
            denial_window_seconds: int = 300,
            exact_novelty: bool | None = None) -> BehaviorProfile:
    """Compute every behavioral signal for an agent from ONE bounded query.

    Replaces five separate round-trips (resource novelty, action novelty, denial
    ratio ×2, volume z-score) with a single windowed fetch of the columns those
    signals need, bucketed and aggregated in Python.

    ``exact_novelty`` controls the novelty/latency trade-off (see
    ``Settings.risk_exact_novelty``): when True, novelty additionally falls back
    to an exact unbounded-history lookup if the resource/action wasn't seen in
    the window — costing up to two extra queries but never mislabelling a
    long-known resource as new.
    """
    settings = get_settings()
    if exact_novelty is None:
        exact_novelty = settings.risk_exact_novelty

    now = datetime.now(timezone.utc)
    span = window_seconds * (lookback_windows + 1)
    horizon = max(span, denial_window_seconds)
    since = now - timedelta(seconds=horizon)

    rows = db.execute(
        select(AuditRecord.created_at, AuditRecord.resource,
               AuditRecord.action_type, AuditRecord.decision)
        .where(AuditRecord.agent_id == agent_id,
               AuditRecord.created_at >= since,
               AuditRecord.billable.is_(True))
        .order_by(AuditRecord.seq.desc())
        .limit(settings.risk_profile_max_rows)
    ).all()

    prof = BehaviorProfile(sample_size=len(rows))
    buckets = [0] * (lookback_windows + 1)
    denial_total = denial_denied = 0
    denial_cutoff = now - timedelta(seconds=denial_window_seconds)
    streak_active = True
    family = resource_family(resource)

    for ts, res, act, decision in rows:
        if ts is not None and ts.tzinfo is None:  # SQLite returns naive UTC
            ts = ts.replace(tzinfo=timezone.utc)
        if res == resource:
            prof.resource_seen = True
        # Family match: `db:customers:1043` is not a NEW KIND of access if the
        # agent already reads `db:customers:<other id>`. Without this, an agent
        # legitimately walking N records scores "novel" N times — the single
        # largest source of risk-scoring noise.
        if not prof.family_seen and resource_family(res) == family:
            prof.family_seen = True
        if act == action_type:
            prof.action_seen = True
        # Rows arrive newest-first: count the leading run of identical
        # (action, resource) pairs — an agent stuck in a tool-calling loop.
        if streak_active and res == resource and act == action_type:
            prof.loop_repeats += 1
        elif streak_active:
            streak_active = False
        if ts is None:
            continue
        if ts >= denial_cutoff:
            denial_total += 1
            if decision == Decision.DENY:
                denial_denied += 1
        idx = int((now - ts).total_seconds() // window_seconds)
        if 0 <= idx <= lookback_windows:
            buckets[idx] += 1

    prof.denial_ratio = (denial_denied / denial_total) if denial_total else 0.0
    prof.volume_z = _zscore_from_buckets(buckets)

    # Optional exactness: only pay for extra queries when the window says "new",
    # so the common (already-seen) case still costs a single query.
    if exact_novelty:
        if not prof.resource_seen:
            prof.resource_seen = has_seen_resource(db, agent_id, resource)
            prof.family_seen = prof.family_seen or prof.resource_seen
            prof.exact_novelty = True
        if not prof.action_seen:
            prof.action_seen = has_seen_action(db, agent_id, action_type)
            prof.exact_novelty = True
    return prof
