"""Detect & respond — turn governed decisions into risk alerts + notifications.

Enforcement alone is half the job; a security team also needs to *know* when an
agent misbehaves. On every governed decision this evaluates a small set of
high-signal rules and raises an :class:`Alert` (optionally notifying a webhook —
Slack, PagerDuty, or a generic JSON sink). It is deliberately fail-open: an
alerting error never blocks or breaks a governance decision.
"""

from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .config import get_settings
from . import distributed_state
from .distributed_state import redis_should_dispatch
from .models import Agent, AgentStatus, Alert, AlertSeverity, AuditRecord, Decision
from .webhooks import post_json

_log = logging.getLogger("agentops.alerts")

_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Webhook dedup throttle: last-dispatch time per (org, kind, agent). Used
# directly when distributed_state_backend=memory (the default), and as the
# fallback when Redis is configured but errors — see distributed_state.py.
_dispatch_throttle: dict[tuple, float] = {}
_throttle_lock = threading.Lock()


def reset_alert_throttle() -> None:
    """Clear the webhook dedup throttle (tests)."""
    with _throttle_lock:
        _dispatch_throttle.clear()


def _should_dispatch_in_process(key: tuple, window: int) -> bool:
    now = time.monotonic()
    with _throttle_lock:
        last = _dispatch_throttle.get(key)
        if last is not None and now - last < window:
            return False
        _dispatch_throttle[key] = now
        return True


def _should_dispatch(alert: Alert, window: int) -> bool:
    """True if a webhook for this (org, kind, agent) may fire now (dedup gate).

    Redis-backed when configured, so a fleet of workers dedups against each
    other instead of each sending its own copy of the same notification —
    falls straight through to the in-process gate on any Redis error.
    """
    if window <= 0:
        return True
    key = (alert.org_id, alert.kind, alert.agent_id)

    client = distributed_state.get_client()
    if client is not None:
        result = redis_should_dispatch(client, ":".join(map(str, key)), window)
        if result is not None:
            return result

    return _should_dispatch_in_process(key, window)


def raise_alert(
    db: Session,
    *,
    severity: str,
    kind: str,
    title: str,
    detail: str = "",
    org_id: int | None = None,
    agent: Agent | None = None,
    resource: str = "",
    audit_seq: int | None = None,
) -> Alert:
    alert = Alert(
        org_id=org_id if org_id is not None else (agent.org_id if agent else None),
        severity=severity, kind=kind, title=title, detail=detail,
        agent_id=agent.id if agent else None,
        agent_name=agent.name if agent else "",
        resource=resource, audit_seq=audit_seq,
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)
    _dispatch(alert)
    return alert


def _dispatch(alert: Alert) -> None:
    settings = get_settings()
    url = settings.alert_webhook_url
    if not url:
        return
    if _SEVERITY_RANK.get(alert.severity, 2) < _SEVERITY_RANK.get(
        settings.alert_webhook_min_severity, 2
    ):
        return
    # Dedup: suppress a repeat notification for the same (org, kind, agent)
    # within the window so an incident can't flood the channel.
    if not _should_dispatch(alert, settings.alert_webhook_dedup_window):
        _log.info("alert webhook suppressed (dedup): kind=%s agent=%s",
                  alert.kind, alert.agent_name)
        return
    payload: dict[str, object]
    if "hooks.slack.com" in url:
        payload = {"text": f":rotating_light: *[{alert.severity.upper()}] "
                   f"{alert.title}*\n{alert.detail}\nagent: {alert.agent_name} · "
                   f"resource: {alert.resource}"}
    else:
        payload = {
            "severity": alert.severity, "kind": alert.kind, "title": alert.title,
            "detail": alert.detail, "agent": alert.agent_name,
            "resource": alert.resource, "audit_seq": alert.audit_seq,
            "created_at": alert.created_at.isoformat() if alert.created_at else None,
        }
    # HMAC-signed when webhook_signing_secret is set; swallows transport errors.
    post_json(url, payload)


def _recent_denials(db: Session, agent_id: int, seconds: int) -> int:
    since = datetime.now(timezone.utc) - timedelta(seconds=seconds)
    return db.scalar(
        select(func.count(AuditRecord.id)).where(
            AuditRecord.agent_id == agent_id,
            AuditRecord.decision == Decision.DENY,
            AuditRecord.created_at >= since,
            AuditRecord.billable.is_(True),
        )
    ) or 0


def _maybe_auto_contain(db: Session, agent: Agent, req, audit_record, settings) -> None:
    """Automatically suspend an agent after repeated exfiltration attempts."""
    threshold = settings.auto_suspend_on_exfil_attempts
    if threshold <= 0 or agent.status != AgentStatus.ACTIVE:
        return
    since = datetime.now(timezone.utc) - timedelta(seconds=settings.alert_denial_spike_window)
    attempts = db.scalar(
        select(func.count(Alert.id)).where(
            Alert.agent_id == agent.id,
            Alert.kind == "data_exfiltration",
            Alert.created_at >= since,
        )
    ) or 0
    if attempts >= threshold:
        agent.status = AgentStatus.SUSPENDED
        db.commit()
        raise_alert(
            db, severity=AlertSeverity.CRITICAL, kind="auto_suspend",
            title="Agent auto-suspended after repeated exfiltration attempts",
            detail=f"{attempts} data-exfiltration attempts within "
                   f"{settings.alert_denial_spike_window}s — the agent has been suspended.",
            agent=agent, resource=req.resource, audit_seq=audit_record.seq,
        )


# LLM-security detector names (see agentops.dlp.llm_guard) that indicate an
# attack on the agent rather than a leaked secret.
_LLM_ATTACK_DETECTORS = {
    "prompt_injection", "system_prompt_exfiltration", "jailbreak_persona",
    "jailbreak_dan", "tool_abuse_instruction", "instruction_override_markup",
    "data_exfil_directive", "llm_moderation",
}


def evaluate_decision(db: Session, agent: Agent, decision, req, audit_record,
                      *, risk=None) -> None:
    """Apply alert rules to a just-made decision. Never raises."""
    try:
        settings = get_settings()

        # -1. Adaptive risk: a high score raises a high_risk alert (opt-in).
        threshold = settings.risk_alert_threshold
        if risk is not None and threshold and risk.score >= threshold:
            raise_alert(
                db, severity=AlertSeverity.HIGH, kind="high_risk",
                title=f"High-risk action (score {risk.score})",
                detail=f"'{req.action_type}' on {req.resource} scored {risk.score} "
                       f"({', '.join(risk.factors)}).",
                agent=agent, resource=req.resource, audit_seq=audit_record.seq,
            )

        # 0. LLM-native attack (prompt injection / jailbreak / tool abuse).
        dlp = getattr(decision, "dlp", None)
        if dlp is not None:
            attack = sorted({f.detector for f in dlp.findings
                             if f.detector in _LLM_ATTACK_DETECTORS})
            if attack:
                raise_alert(
                    db, severity=AlertSeverity.HIGH, kind="prompt_injection",
                    title="LLM prompt-injection / jailbreak attempt detected",
                    detail=f"Attack signatures ({', '.join(attack)}) in a "
                           f"'{req.action_type}' payload to {req.resource}.",
                    agent=agent, resource=req.resource, audit_seq=audit_record.seq,
                )

        # 1. Data-exfiltration attempt (DLP blocked an outbound secret/PII).
        dlp_blocking = getattr(getattr(decision, "dlp", None), "blocking", False)
        if decision.decision == Decision.DENY and (
            dlp_blocking or "exfiltration" in (decision.reason or "").lower()
        ):
            leaked = ", ".join(sorted({f.detector for f in decision.dlp.findings})) \
                if decision.dlp else ""
            raise_alert(
                db, severity=AlertSeverity.HIGH, kind="data_exfiltration",
                title="Data-exfiltration attempt blocked",
                detail=f"Agent tried to send sensitive data ({leaked}) to {req.resource}.",
                agent=agent, resource=req.resource, audit_seq=audit_record.seq,
            )
            _maybe_auto_contain(db, agent, req, audit_record, settings)

        # 2. Probing behaviour — a burst of denials from one agent.
        if decision.decision == Decision.DENY:
            denials = _recent_denials(db, agent.id, settings.alert_denial_spike_window)
            if denials == settings.alert_denial_spike_count:  # fire once, at the threshold
                raise_alert(
                    db, severity=AlertSeverity.MEDIUM, kind="denial_spike",
                    title="Agent showing probing behaviour",
                    detail=f"{denials} denied actions in the last "
                           f"{settings.alert_denial_spike_window}s.",
                    agent=agent, resource=req.resource, audit_seq=audit_record.seq,
                )
    except Exception:  # fail-open: alerting must not break governance
        _log.exception("alert evaluation failed")
        db.rollback()
