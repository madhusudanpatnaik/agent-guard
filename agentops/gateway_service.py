"""Gateway orchestration — the enforcement point every agent action flows through.

This ties the subsystems together for a single authorization decision:

    DLP scan  ->  Policy engine (RBAC + constraints)  ->  quota  ->  ledger  ->  approval

It is deliberately separated from the HTTP router so it can be unit-tested and
reused by the in-process SDK, a sidecar, or a future gRPC surface.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from .alerts_service import evaluate_decision
from .approvals_service import notify_pending as notify_pending_approval
from .audit.ledger import AuditLedger
from .config import get_settings
from .containment import active as containment_active
from .counters import get_rate_backend
from . import distributed_state
from .distributed_state import redis_get_detectors, redis_invalidate_detectors, redis_set_detectors
from .dlp.providers import scan_with_providers
from .dlp.scanner import DLPFinding, MEDIUM, scan_payload
from .egress import check_egress
from .models import (
    Agent,
    ApprovalStatus,
    AuditRecord,
    Connector,
    ConnectorAuth,
    Decision,
    Organization,
    Policy,
    Approval,
)
from .policy.engine import ActionRequest, PolicyDecision, PolicyEngine
from .policy.external import get_external_engine
from .resilience import UpstreamUnavailable, get_breaker, resilient_request
from .risk import RiskAssessment, assess as risk_assess
from .tracing import inject_context, span
from .utils import build_preview, canonical_json, payload_fingerprint
from .vault import decrypt_secret


# Per-org custom-detector cache. Detectors are edited by an operator (rare) but
# read on EVERY authorization, so an uncached lookup is a pure per-request tax.
# A short TTL bounds staleness without needing cross-process invalidation: a new
# detector becomes active within the TTL, and the write path clears it locally.
# When distributed_state_backend=redis, invalidation is exact instead of
# TTL-bounded: every worker sees a write on its very next request, not just
# the worker that made it — see distributed_state.py.
_DETECTOR_TTL_SECONDS = 30.0
_detector_cache: dict[int | None, tuple[float, list[dict]]] = {}
_detector_lock = threading.Lock()


def invalidate_detector_cache(org_id: int | None = None) -> None:
    """Drop cached detectors (call after a detector write; all orgs if None)."""
    with _detector_lock:
        if org_id is None:
            _detector_cache.clear()
        else:
            _detector_cache.pop(org_id, None)

    client = distributed_state.get_client()
    if client is not None:
        redis_invalidate_detectors(client, org_id)


def _load_custom_detectors(db: Session, org_id: int | None) -> list[dict]:
    """Enabled operator-defined DLP detectors for an org (empty if none)."""
    from .models import Detector

    client = distributed_state.get_client()
    if client is not None:
        cached = redis_get_detectors(client, org_id)
        if cached is not None:
            return cached

    now = time.monotonic()
    with _detector_lock:
        hit = _detector_cache.get(org_id)
        if hit is not None and now - hit[0] < _DETECTOR_TTL_SECONDS:
            return hit[1]

    rows = db.scalars(
        select(Detector).where(Detector.org_id == org_id, Detector.enabled.is_(True))
    )
    specs = [{"name": d.name, "pattern": d.pattern, "severity": d.severity} for d in rows]
    with _detector_lock:
        _detector_cache[org_id] = (now, specs)
    if client is not None:
        redis_set_detectors(client, org_id, specs, _DETECTOR_TTL_SECONDS)
    return specs


def _scan_request_payload(payload, custom_detectors=None):
    """DLP-scan an agent request payload with a hard size bound.

    Oversized bodies are scanned truncated (as text) so a huge payload cannot
    exhaust CPU/regex/threadpool, and the truncation is itself flagged. Any
    org-defined custom detectors are merged with the built-ins.
    """
    limit = get_settings().max_request_scan_bytes
    serialized = canonical_json(payload)
    if len(serialized) <= limit:
        return scan_with_providers(payload, custom_detectors)
    result = scan_with_providers(serialized[:limit], custom_detectors)
    result.findings.append(
        DLPFinding(
            detector="oversized_payload",
            severity=MEDIUM,
            count=1,
            sample=f"{len(serialized)} bytes (scan bounded to {limit})",
            path="$",
        )
    )
    return result


@dataclass
class AuthorizationResult:
    decision: PolicyDecision
    audit_record: AuditRecord
    approval: Approval | None = None
    risk: "RiskAssessment | None" = None


def _recent_action_count(db: Session, agent_id: int, seconds: int) -> int:
    """Count an agent's *billable* actions in the window.

    Derivative rows (upstream results, human approvals) are excluded so a single
    enforced call or an operator approval does not inflate quota / rate usage.
    Routed through the configured :mod:`agentops.counters` backend (DB by
    default; Redis sliding window for horizontally scaled deployments).
    """
    return get_rate_backend().count(db, agent_id, seconds)


def _attribute_context(agent: Agent, req: ActionRequest) -> dict[str, Any]:
    """Build the ABAC attribute context for a request.

    Subject + environment attributes are derived from the authenticated agent
    and the clock (never spoofable by the caller); any caller-supplied
    ``req.attributes`` (e.g. resource tags) are merged on top, but the trusted
    ``subject``/``env`` namespaces always win.
    """
    now = datetime.now(timezone.utc)
    trusted = {
        "subject": {
            "id": agent.id,
            "name": agent.name,
            "role": agent.role.name if agent.role else None,
            "owner": agent.owner,
            "org_id": agent.org_id,
            "status": agent.status,
        },
        "env": {
            "utc_hour": now.hour,
            "weekday": now.weekday(),  # 0=Mon
        },
    }
    context: dict[str, Any] = dict(req.attributes or {})
    context.update(trusted)  # trusted namespaces override anything caller-supplied
    return context


def _resolve_step_up_threshold(global_threshold: int, policies: list[Policy],
                               matched_policy_id: int | None) -> int:
    """Per-policy risk step-up override, falling back to the global threshold.

    If the winning policy declares ``conditions["risk_step_up"]`` that value wins
    (including 0, which disables step-up for that policy); otherwise the global
    ``risk_step_up_threshold`` applies.
    """
    if matched_policy_id is not None:
        matched = next((p for p in policies if p.id == matched_policy_id), None)
        cond = matched.conditions if matched and isinstance(matched.conditions, dict) else {}
        if "risk_step_up" in cond:
            try:
                return int(cond["risk_step_up"])
            except (TypeError, ValueError):
                return global_threshold
    return global_threshold


def authorize_action(
    db: Session, agent: Agent, req: ActionRequest, *, pre_approved: bool = False
) -> AuthorizationResult:
    settings = get_settings()
    engine = PolicyEngine(
        default_deny=settings.default_deny,
        block_egress_on_secret=settings.dlp_block_egress_on_secret,
    )
    ledger = AuditLedger(db)

    role = agent.role
    policies: list[Policy] = list(role.policies) if role else []

    # Populate the ABAC attribute context (subject/env are trusted, server-set).
    req.attributes = _attribute_context(agent, req)

    # DLP scan once (size-bounded); reuse for the decision and the audit preview.
    # Org custom detectors are merged with the built-ins on this path.
    custom_detectors = _load_custom_detectors(db, agent.org_id)
    with span("agentops.dlp.scan", **{"agentops.resource": req.resource}):
        dlp = _scan_request_payload(req.payload, custom_detectors)

    now = datetime.now(timezone.utc)

    # Emergency kill switch: if the agent's org is contained, deny everything
    # up front — a fleet-wide freeze that overrides any allow policy. A time-bound
    # freeze auto-lifts once its window elapses (handled in containment.active).
    org = db.get(Organization, agent.org_id) if agent.org_id is not None else None
    if org is not None and containment_active(db, org):
        decision = PolicyDecision(
            Decision.DENY,
            f"Organization is contained (emergency freeze){f': {org.contained_reason}' if org.contained_reason else ''}."
            " All agent actions are denied until containment is lifted.",
            dlp=dlp,
        )
        record = ledger.append(
            agent_id=agent.id, agent_name=agent.name, role_name=role.name if role else "",
            action_type=req.action_type, resource=req.resource,
            decision=decision.decision, reason=decision.reason,
            payload_hash=payload_fingerprint(req.payload),
            payload_preview=build_preview(dlp.redacted),
            dlp_findings=dlp.findings_as_dicts(), org_id=agent.org_id,
        )
        return AuthorizationResult(decision=decision, audit_record=record)

    # Global per-agent quota (defense against runaway loops), evaluated first.
    quota_used = _recent_action_count(db, agent.id, settings.quota_window_seconds)
    if quota_used >= agent.quota:
        decision = PolicyDecision(
            Decision.DENY,
            f"Agent quota exhausted: {quota_used}/{agent.quota} actions in the last "
            f"{settings.quota_window_seconds}s.",
            dlp=dlp,
        )
    else:
        external = get_external_engine()
        if external is not None:
            # Policy-as-code: OPA/Cedar owns the RBAC verdict; AgentOps still
            # enforces DLP egress blocking, quotas, approvals, and the ledger.
            decision = external.evaluate(req, dlp=dlp)
        else:
            decision = engine.evaluate(
                req,
                policies,
                now=now,
                rate_counter=lambda secs: _recent_action_count(db, agent.id, secs),
                dlp=dlp,
            )

    # A previously granted human approval satisfies the approval obligation — but
    # never overrides a hard deny (policy deny or DLP exfiltration block).
    if pre_approved and decision.decision == Decision.REQUIRE_APPROVAL:
        decision = PolicyDecision(
            Decision.ALLOW,
            f"Proceeding under prior human approval. ({decision.reason})",
            matched_policy_id=decision.matched_policy_id,
            obligations=decision.obligations,
            dlp=dlp,
        )

    # Adaptive risk scoring — a continuous 0–100 signal from behavioral baselines
    # + DLP + egress + amount + novelty. It never loosens a decision; above the
    # step-up threshold it *escalates* a fresh ALLOW to human review. A matched
    # policy may override the global threshold via conditions["risk_step_up"]
    # (a lower value tightens a sensitive rule; 0 disables step-up for it) so a
    # team can require sign-off on payments without turning it on fleet-wide.
    risk: RiskAssessment | None = None
    if settings.risk_scoring_enabled:
        risk = risk_assess(db, agent, req, decision, now=now)
        threshold = _resolve_step_up_threshold(
            settings.risk_step_up_threshold, policies, decision.matched_policy_id)
        if (threshold and risk.score >= threshold
                and decision.decision == Decision.ALLOW and not pre_approved):
            decision = PolicyDecision(
                Decision.REQUIRE_APPROVAL,
                f"Adaptive step-up: risk score {risk.score} ≥ {threshold} "
                f"({', '.join(risk.factors)}) — human sign-off required.",
                matched_policy_id=decision.matched_policy_id,
                obligations=decision.obligations,
                dlp=dlp,
            )

    record = ledger.append(
        agent_id=agent.id,
        agent_name=agent.name,
        role_name=role.name if role else "",
        action_type=req.action_type,
        resource=req.resource,
        decision=decision.decision,
        reason=decision.reason,
        payload_hash=payload_fingerprint(req.payload),
        payload_preview=build_preview(dlp.redacted),
        dlp_findings=dlp.findings_as_dicts(),
        matched_policy_id=decision.matched_policy_id,
        org_id=agent.org_id,
        risk_score=risk.score if risk else 0,
        risk_factors=risk.factors if risk else None,
    )
    # Record the billable action in the rate backend (no-op for the DB backend;
    # a ZADD for Redis so the sliding window reflects this request going forward).
    get_rate_backend().observe(db, agent.id)

    approval: Approval | None = None
    if decision.decision == Decision.REQUIRE_APPROVAL:
        approval = Approval(
            org_id=agent.org_id,
            agent_id=agent.id,
            agent_name=agent.name,
            action_type=req.action_type,
            resource=req.resource,
            payload_preview=build_preview(dlp.redacted),
            reason=decision.reason,
            status=ApprovalStatus.PENDING,
            audit_record_id=record.id,
            expires_at=now + timedelta(seconds=settings.approval_ttl_seconds),
        )
        db.add(approval)
        db.commit()
        db.refresh(approval)
        # Tell operators a decision is waiting (best-effort, signed webhook).
        notify_pending_approval(approval)

    # Detect & respond: raise risk alerts for this decision (fail-open).
    evaluate_decision(db, agent, decision, req, record, risk=risk)

    return AuthorizationResult(decision=decision, audit_record=record,
                               approval=approval, risk=risk)


# --------------------------------------------------------------------------- #
# Enforced execution — the plane calls the upstream ON BEHALF of the agent
# --------------------------------------------------------------------------- #

# Response/request headers we refuse to forward in either direction.
_HOP_BY_HOP = {"host", "content-length", "connection", "authorization", "cookie", "set-cookie"}
_SAFE_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}


@dataclass
class ExecutionResult:
    executed: bool
    decision: PolicyDecision
    audit_record: AuditRecord
    approval: Approval | None = None
    status_code: int | None = None
    response_headers: dict[str, str] = field(default_factory=dict)
    response_body: Any = None
    response_dlp_findings: list[dict] = field(default_factory=list)
    upstream_error: str | None = None


def _validate_path(path: str) -> str:
    """Force the agent-supplied target to stay a *path* under the connector.

    Rejecting absolute URLs stops an agent from pivoting a trusted connector to
    another host. Rejecting ``..`` segments is equally important: otherwise the
    policy check (which sees the raw path) and the actual request (which sees the
    URL-normalized path) can diverge — e.g. ``/customers/..`` is authorized as
    ``http:crm/customers/..`` but really hits ``/`` — a policy bypass.
    """
    if not path:
        return "/"
    parsed = urlparse(path)
    if parsed.scheme or parsed.netloc:
        raise ValueError("path must be relative to the connector base_url, not an absolute URL")
    normalized = path if path.startswith("/") else "/" + path
    if ".." in normalized.split("/"):
        raise ValueError("path must not contain '..' traversal segments")
    return normalized


def _inject_auth(connector: Connector, headers: dict[str, str]) -> dict[str, str]:
    secret = decrypt_secret(connector.auth_secret_encrypted)
    if connector.auth_type == ConnectorAuth.BEARER:
        headers["Authorization"] = f"Bearer {secret}"
    elif connector.auth_type == ConnectorAuth.BASIC:
        headers["Authorization"] = f"Basic {secret}"
    elif connector.auth_type == ConnectorAuth.HEADER:
        headers[connector.auth_header_name or "Authorization"] = secret
    return headers


def _scan_response(text: str) -> tuple[Any, list[dict]]:
    """DLP-scan an upstream response; return (redacted_body, findings)."""
    import json

    try:
        parsed: Any = json.loads(text)
    except (ValueError, TypeError):
        parsed = text
    result = scan_payload(parsed)
    return (result.redacted if result.has_findings else parsed), result.findings_as_dicts()


def _claim_approval(db: Session, approval_id, agent: Agent, resource: str, action_type: str) -> bool:
    """Atomically claim (consume) the caller's approval for this exact action.

    A single ``UPDATE ... WHERE status='approved'`` is a compare-and-swap: under
    concurrent execute() calls with the same approval_id, exactly one wins
    (rowcount == 1) and may proceed. This closes the read-then-write TOCTOU that
    would otherwise allow an approved high-stakes action to execute twice.
    """
    if approval_id is None:
        return False
    result = db.execute(
        update(Approval)
        .where(
            Approval.id == approval_id,
            Approval.agent_id == agent.id,
            Approval.status == ApprovalStatus.APPROVED,
            Approval.resource == resource,
            Approval.action_type == action_type,
        )
        .values(status=ApprovalStatus.USED)
    )
    db.commit()
    return (getattr(result, "rowcount", 0) or 0) == 1


def _restore_approval(db: Session, approval_id, agent: Agent, resource: str,
                      action_type: str) -> None:
    """Return a just-claimed approval to APPROVED when the action didn't run.

    The compare-and-swap in :func:`_claim_approval` prevents double-execution;
    but if the post-claim authorization still denies (quota/containment/policy),
    the action never executes, so the human sign-off should not be spent. This
    flips it back (guarded on status=USED so it can't resurrect a genuinely
    consumed approval).
    """
    if approval_id is None:
        return
    db.execute(
        update(Approval)
        .where(
            Approval.id == approval_id,
            Approval.agent_id == agent.id,
            Approval.status == ApprovalStatus.USED,
            Approval.resource == resource,
            Approval.action_type == action_type,
        )
        .values(status=ApprovalStatus.APPROVED)
    )
    db.commit()


def execute_action(
    db: Session,
    agent: Agent,
    *,
    connector_name: str,
    method: str,
    path: str,
    headers: dict[str, str] | None = None,
    body: Any = None,
    metadata: dict[str, Any] | None = None,
    approval_id: int | None = None,
) -> ExecutionResult:
    """Authorize AND, if permitted, execute the call against the upstream.

    The agent supplies only the connector name, method, path and body — never the
    credential or base URL. The plane decides, injects the secret, calls out,
    scans the response, and returns a sanitized result.
    """
    settings = get_settings()
    method = (method or "GET").upper()
    if method not in _SAFE_METHODS:
        raise ValueError(f"unsupported method {method}")

    connector = db.scalar(
        select(Connector).where(
            Connector.name == connector_name, Connector.org_id == agent.org_id
        )
    )
    if not connector or not connector.enabled:
        raise ValueError(f"unknown or disabled connector '{connector_name}'")
    check_egress(connector.base_url)  # SSRF guard (no-op unless enabled)

    safe_path = _validate_path(path)
    resource = f"http:{connector.name}{safe_path}"
    req = ActionRequest(
        action_type=f"http.{method.lower()}",
        resource=resource,
        payload=body,
        metadata=metadata or {},
    )

    # Was this action already signed off by a human? Claim the approval atomically
    # (single-use); the winner of any concurrent race is the only one that proceeds.
    claimed = _claim_approval(db, approval_id, agent, resource, req.action_type)
    auth = authorize_action(db, agent, req, pre_approved=claimed)

    if auth.decision.decision != Decision.ALLOW:
        # Denied or awaiting approval — the upstream is NEVER called. If we
        # consumed a human approval above but the action still won't run (quota
        # exhausted, org contained, or the policy now denies), give the approval
        # back so the operator's sign-off isn't permanently burned for nothing.
        if claimed:
            _restore_approval(db, approval_id, agent, resource, req.action_type)
        return ExecutionResult(
            executed=False,
            decision=auth.decision,
            audit_record=auth.audit_record,
            approval=auth.approval,
        )

    # --- permitted: the plane makes the real call, injecting the credential ---
    fwd_headers = {
        k: v for k, v in (headers or {}).items() if k.lower() not in _HOP_BY_HOP
    }
    fwd_headers = _inject_auth(connector, fwd_headers)
    # Propagate W3C trace context so the upstream call joins the same trace.
    fwd_headers = inject_context(fwd_headers)
    url = urljoin(connector.base_url.rstrip("/") + "/", safe_path.lstrip("/"))

    ledger = AuditLedger(db)
    breaker = get_breaker(
        connector.name, fail_threshold=settings.circuit_fail_threshold,
        cooldown_seconds=settings.circuit_cooldown_seconds)
    try:
        with span("agentops.upstream.call",
                  **{"http.method": method, "agentops.connector": connector.name}), \
                httpx.Client(timeout=15.0, follow_redirects=False) as client:
            resp = resilient_request(
                breaker,
                # `json=None` means "no body"; test None explicitly so a
                # legitimately-falsy body ({}, [], "", 0) is still transmitted
                # and matches what was DLP-scanned/authorized/hashed.
                lambda: client.request(method, url, headers=fwd_headers,
                                       json=body if body is not None else None),
                retries=settings.upstream_max_retries,
                backoff=settings.upstream_retry_backoff,
            )
        raw = resp.text[: connector.max_response_bytes]
        redacted_body, resp_findings = _scan_response(raw)
        status_code = resp.status_code
        safe_headers = {
            k: v for k, v in resp.headers.items() if k.lower() not in _HOP_BY_HOP
        }
    except (httpx.HTTPError, UpstreamUnavailable) as exc:
        ledger.append(
            agent_id=agent.id, agent_name=agent.name,
            role_name=agent.role.name if agent.role else "",
            action_type=f"{req.action_type}.result", resource=resource,
            decision=Decision.DENY, reason=f"Upstream call failed: {exc}",
            billable=False, org_id=agent.org_id,
        )
        return ExecutionResult(
            executed=False, decision=auth.decision, audit_record=auth.audit_record,
            upstream_error=str(exc),
        )

    # Record the execution result (with response-side DLP) as its own ledger link.
    ledger.append(
        agent_id=agent.id, agent_name=agent.name,
        role_name=agent.role.name if agent.role else "",
        action_type=f"{req.action_type}.result", resource=resource,
        decision=Decision.ALLOW,
        reason=f"Upstream {method} {resource} -> {status_code}"
        + (f"; {len(resp_findings)} DLP finding(s) redacted from response" if resp_findings else ""),
        payload_hash=payload_fingerprint(raw),
        payload_preview=build_preview(redacted_body),
        dlp_findings=resp_findings,
        billable=False, org_id=agent.org_id,
    )

    return ExecutionResult(
        executed=True,
        decision=auth.decision,
        audit_record=auth.audit_record,
        status_code=status_code,
        response_headers=safe_headers,
        response_body=redacted_body,
        response_dlp_findings=resp_findings,
    )
