"""Approval lifecycle helpers — lazy expiry + pending-request notifications.

Rather than depend on a background worker, pending approvals carry an
``expires_at`` and are transitioned to ``expired`` the moment anyone reads or
acts on them past that time. This keeps the queue truthful and prevents an old
"pending" from being approved (and executed) long after it was requested.

A pending approval also notifies operators (signed webhook, Slack-formatted for
Slack URLs) so a human actually knows a decision is waiting — without which
human-in-the-loop stalls silently.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import get_settings
from .models import Approval, ApprovalStatus
from .webhooks import post_json

_log = logging.getLogger("agentops.approvals")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _is_stale(appr: Approval, now: datetime) -> bool:
    if appr.status != ApprovalStatus.PENDING or appr.expires_at is None:
        return False
    exp = appr.expires_at
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)
    return exp < now


def expire_if_stale(db: Session, appr: Approval) -> Approval:
    """Flip a single approval to ``expired`` if its TTL has passed."""
    if _is_stale(appr, _now()):
        appr.status = ApprovalStatus.EXPIRED
        appr.resolution_note = "Expired: no operator decision within the approval window."
        appr.resolved_at = _now()
        db.commit()
        db.refresh(appr)
    return appr


def notify_pending(approval: Approval) -> None:
    """Notify operators that an approval is waiting (best-effort, never raises).

    Uses ``approval_webhook_url`` if set, else falls back to the alert webhook;
    if neither is configured nothing is sent. The webhook is HMAC-signed when a
    signing secret is configured.
    """
    settings = get_settings()
    url = settings.approval_webhook_url or settings.alert_webhook_url
    if not url:
        return
    expires = approval.expires_at.isoformat() if approval.expires_at else None
    if "hooks.slack.com" in url:
        payload: dict[str, object] = {
            "text": f":hourglass_flowing_sand: *Approval needed* — "
                    f"{approval.action_type} on {approval.resource}\n"
                    f"agent: {approval.agent_name} · reason: {approval.reason}\n"
                    f"approval id: {approval.id}"
        }
    else:
        payload = {
            "event": "approval.pending", "approval_id": approval.id,
            "agent": approval.agent_name, "action_type": approval.action_type,
            "resource": approval.resource, "reason": approval.reason,
            "expires_at": expires,
        }
    try:
        post_json(url, payload)
    except Exception as exc:  # noqa: BLE001 — a notification outage must not block governance
        _log.warning("approval notification failed: %s", exc)


def sweep_expired(db: Session) -> int:
    """Expire every stale pending approval; returns how many were expired."""
    now = _now()
    stale = db.scalars(
        select(Approval).where(Approval.status == ApprovalStatus.PENDING)
    )
    count = 0
    for appr in stale:
        if _is_stale(appr, now):
            appr.status = ApprovalStatus.EXPIRED
            appr.resolution_note = "Expired: no operator decision within the approval window."
            appr.resolved_at = now
            count += 1
    if count:
        db.commit()
    return count
