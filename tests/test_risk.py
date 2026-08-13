"""Tests for adaptive risk scoring, behavioral anomaly detection, and step-up."""

from agentguard import anomaly, risk
from agentguard.audit.ledger import AuditLedger
from agentguard.config import get_settings
from agentguard.dlp.scanner import scan_payload
from agentguard.models import Agent, Decision, Effect, Policy, Role
from agentguard.policy.engine import ActionRequest, PolicyDecision


def _agent(db, quota=10000):
    role = Role(name="r")
    db.add(role)
    db.flush()
    db.add(Policy(role_id=role.id, effect=Effect.ALLOW, resource="**", actions=["*"]))
    a = Agent(name="a", role_id=role.id, api_key_hash="h", api_key_prefix="p", quota=quota)
    db.add(a)
    db.commit()
    db.refresh(a)
    return a


# --- anomaly primitives -----------------------------------------------------

def test_novel_resource_and_action(db):
    a = _agent(db)
    assert anomaly.has_seen_resource(db, a.id, "db:x") is False
    AuditLedger(db).append(agent_id=a.id, agent_name="a", role_name="r",
                           action_type="read", resource="db:x",
                           decision=Decision.ALLOW, reason="", billable=True)
    assert anomaly.has_seen_resource(db, a.id, "db:x") is True
    assert anomaly.has_seen_action(db, a.id, "read") is True
    assert anomaly.has_seen_action(db, a.id, "delete") is False


def test_off_hours():
    from datetime import datetime, timezone
    assert anomaly.is_off_hours(datetime(2026, 1, 1, 3, 0, tzinfo=timezone.utc)) is True
    assert anomaly.is_off_hours(datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)) is False


def _insert_at(db, agent_id, seconds_ago, n=1):
    """Insert n billable audit rows created `seconds_ago` in the past."""
    from datetime import datetime, timedelta, timezone
    from sqlalchemy import func, select
    from agentguard.models import AuditRecord
    ts = datetime.now(timezone.utc) - timedelta(seconds=seconds_ago)
    max_seq = db.scalar(select(func.max(AuditRecord.seq)))  # 0 is falsy — check None explicitly
    next_seq = 0 if max_seq is None else max_seq + 1
    for i in range(n):
        db.add(AuditRecord(seq=next_seq + i, agent_id=agent_id, decision="allow",
                           billable=True, created_at=ts))
    db.commit()


def test_volume_zscore_detects_surge(db):
    a = _agent(db)
    # Baseline: ~1 action per 300s window across the lookback history.
    for w in range(1, 13):
        _insert_at(db, a.id, seconds_ago=300 * w + 10, n=1)
    # Surge: 20 actions in the current window.
    _insert_at(db, a.id, seconds_ago=5, n=20)
    z = anomaly.volume_zscore(db, a.id)
    assert z >= 3.0  # clear surge vs. the agent's own norm


def test_volume_zscore_flat_traffic_is_low(db):
    a = _agent(db)
    for w in range(0, 13):
        _insert_at(db, a.id, seconds_ago=300 * w + 10, n=2)  # steady 2/window
    assert anomaly.volume_zscore(db, a.id) < 3.0


def test_volume_zscore_runs_a_single_query(db):
    from sqlalchemy import event
    a = _agent(db)
    for w in range(0, 13):
        _insert_at(db, a.id, seconds_ago=300 * w + 10, n=1)
    counter = {"n": 0}

    def _count(conn, cursor, statement, params, context, executemany):
        if statement.lstrip().upper().startswith("SELECT"):
            counter["n"] += 1

    engine = db.get_bind()
    event.listen(engine, "before_cursor_execute", _count)
    try:
        anomaly.volume_zscore(db, a.id)
    finally:
        event.remove(engine, "before_cursor_execute", _count)
    assert counter["n"] == 1  # was 13 (one COUNT per window) before the fix


def test_denial_ratio(db):
    a = _agent(db)
    led = AuditLedger(db)
    for dec in (Decision.ALLOW, Decision.DENY, Decision.DENY, Decision.DENY):
        led.append(agent_id=a.id, agent_name="a", role_name="r", action_type="x",
                   resource="r", decision=dec, reason="", billable=True)
    assert anomaly.recent_denial_ratio(db, a.id) == 0.75


# --- risk scoring -----------------------------------------------------------

def test_clean_routine_action_is_low_risk(db):
    a = _agent(db)
    # Seed history so the resource/action aren't novel.
    AuditLedger(db).append(agent_id=a.id, agent_name="a", role_name="r",
                           action_type="db.read", resource="db:x",
                           decision=Decision.ALLOW, reason="", billable=True)
    from datetime import datetime, timezone
    noon = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    req = ActionRequest("db.read", "db:x")
    d = PolicyDecision(Decision.ALLOW, "ok", dlp=scan_payload(None))
    r = risk.assess(db, a, req, d, now=noon)
    assert r.score < 20


def test_secret_egress_is_high_risk(db):
    a = _agent(db)
    from datetime import datetime, timezone
    noon = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    req = ActionRequest("http.post", "http:evil/exfil", payload={"k": "AKIAIOSFODNN7EXAMPLE"})
    dlp = scan_payload({"k": "AKIAIOSFODNN7EXAMPLE"})
    d = PolicyDecision(Decision.DENY, "blocked", dlp=dlp)
    r = risk.assess(db, a, req, d, now=noon)
    # critical DLP (40) + egress (15) + novel resource (15) + novel action (8) = 78
    assert r.score >= 70
    assert "egress" in r.factors
    assert any(f.startswith("dlp_") for f in r.factors)


def test_amount_and_off_hours_add_risk(db):
    a = _agent(db)
    AuditLedger(db).append(agent_id=a.id, agent_name="a", role_name="r",
                           action_type="payment.refund", resource="pay:x",
                           decision=Decision.ALLOW, reason="", billable=True)
    from datetime import datetime, timezone
    night = datetime(2026, 1, 1, 3, 0, tzinfo=timezone.utc)
    req = ActionRequest("payment.refund", "pay:x", metadata={"amount": 4000})
    d = PolicyDecision(Decision.ALLOW, "ok", dlp=scan_payload(None))
    r = risk.assess(db, a, req, d, now=night)
    assert "off_hours" in r.factors
    assert any(f.startswith("amount:") for f in r.factors)


# --- adaptive step-up (end-to-end) ------------------------------------------

def test_step_up_escalates_high_risk_allow_to_approval(client, admin_headers, monkeypatch):
    monkeypatch.setattr(get_settings(), "risk_step_up_threshold", 35)
    role = client.post("/api/roles", json={"name": "risky"}, headers=admin_headers).json()
    rid = role["id"]
    # Broadly allow egress so policy says ALLOW; risk should then escalate it.
    client.post(f"/api/roles/{rid}/policies", headers=admin_headers, json={
        "effect": "allow", "resource": "http:**", "actions": ["http.post"]})
    agent = client.post("/api/agents", json={"name": "RiskBot", "role_id": rid},
                        headers=admin_headers).json()
    # Novel resource + egress -> risk >= 40 -> stepped up to approval.
    r = client.post("/api/v1/gateway/authorize", headers={"X-API-Key": agent["api_key"]},
                    json={"action_type": "http.post", "resource": "http:new-partner/hook",
                          "payload": {"note": "hello"}}).json()
    assert r["decision"] == "require_approval"
    assert r["risk_score"] >= 35
    assert r["approval_id"]


def test_step_up_off_by_default_preserves_allow(client, admin_headers):
    role = client.post("/api/roles", json={"name": "plain"}, headers=admin_headers).json()
    rid = role["id"]
    client.post(f"/api/roles/{rid}/policies", headers=admin_headers, json={
        "effect": "allow", "resource": "http:**", "actions": ["http.post"]})
    agent = client.post("/api/agents", json={"name": "PlainBot", "role_id": rid},
                        headers=admin_headers).json()
    r = client.post("/api/v1/gateway/authorize", headers={"X-API-Key": agent["api_key"]},
                    json={"action_type": "http.post", "resource": "http:new/hook",
                          "payload": {"note": "hi"}}).json()
    assert r["decision"] == "allow"  # threshold 0 => risk never changes the decision
    assert r["risk_score"] is not None  # but the score is still reported


def test_per_policy_step_up_overrides_global_off(client, admin_headers):
    # Global step-up is OFF (default 0), but a sensitive policy sets its own
    # threshold — so novel egress on THAT policy is escalated while others aren't.
    role = client.post("/api/roles", json={"name": "perpol"}, headers=admin_headers).json()
    rid = role["id"]
    client.post(f"/api/roles/{rid}/policies", headers=admin_headers, json={
        "effect": "allow", "resource": "http:pay/**", "actions": ["http.post"],
        "conditions": {"risk_step_up": 30}})
    client.post(f"/api/roles/{rid}/policies", headers=admin_headers, json={
        "effect": "allow", "resource": "http:safe/**", "actions": ["http.post"]})
    agent = client.post("/api/agents", json={"name": "PPBot", "role_id": rid},
                        headers=admin_headers).json()
    key = {"X-API-Key": agent["api_key"]}
    # Sensitive policy: novel egress scores >= 30 -> stepped up.
    pay = client.post("/api/v1/gateway/authorize", headers=key,
                      json={"action_type": "http.post", "resource": "http:pay/charge",
                            "payload": {"n": "x"}}).json()
    assert pay["decision"] == "require_approval"
    assert pay["risk_score"] >= 30
    # Other policy (no override, global off): same risk, but allowed.
    safe = client.post("/api/v1/gateway/authorize", headers=key,
                       json={"action_type": "http.post", "resource": "http:safe/ping",
                             "payload": {"n": "x"}}).json()
    assert safe["decision"] == "allow"


def test_per_policy_step_up_zero_disables_for_that_policy(client, admin_headers, monkeypatch):
    # Global step-up is ON (low), but a policy opts OUT with risk_step_up=0.
    monkeypatch.setattr(get_settings(), "risk_step_up_threshold", 20)
    role = client.post("/api/roles", json={"name": "optout"}, headers=admin_headers).json()
    rid = role["id"]
    client.post(f"/api/roles/{rid}/policies", headers=admin_headers, json={
        "effect": "allow", "resource": "http:trusted/**", "actions": ["http.post"],
        "conditions": {"risk_step_up": 0}})
    agent = client.post("/api/agents", json={"name": "OOBot", "role_id": rid},
                        headers=admin_headers).json()
    r = client.post("/api/v1/gateway/authorize", headers={"X-API-Key": agent["api_key"]},
                    json={"action_type": "http.post", "resource": "http:trusted/x",
                          "payload": {"n": "x"}}).json()
    # Novel egress would exceed the global 20, but this policy disables step-up.
    assert r["decision"] == "allow"
    assert r["risk_score"] >= 20


def test_risk_alert_raised_above_threshold(client, admin_headers, monkeypatch):
    monkeypatch.setattr(get_settings(), "risk_alert_threshold", 30)
    role = client.post("/api/roles", json={"name": "ra"}, headers=admin_headers).json()
    rid = role["id"]
    client.post(f"/api/roles/{rid}/policies", headers=admin_headers, json={
        "effect": "allow", "resource": "http:**", "actions": ["http.post"]})
    agent = client.post("/api/agents", json={"name": "RA", "role_id": rid},
                        headers=admin_headers).json()
    client.post("/api/v1/gateway/authorize", headers={"X-API-Key": agent["api_key"]},
                json={"action_type": "http.post", "resource": "http:novel/x",
                      "payload": {"note": "hi"}})
    alerts = client.get("/api/alerts", headers=admin_headers).json()
    assert any(a["kind"] == "high_risk" for a in alerts)


# --- family-aware novelty (alert-fatigue reduction) --------------------------

def test_walking_ids_in_a_known_family_is_not_repeatedly_novel(db):
    """An agent reading customer 1..N must not score 'novel' every single time."""
    a = _agent(db)
    led = AuditLedger(db)
    # The agent has already read one customer record.
    led.append(agent_id=a.id, agent_name="a", role_name="r", action_type="db.read",
               resource="db:customers:1001", decision=Decision.ALLOW, reason="",
               billable=True)
    from datetime import datetime, timezone
    noon = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    d = PolicyDecision(Decision.ALLOW, "ok", dlp=scan_payload(None))

    # A DIFFERENT id in the same family is the same kind of access -> not novel.
    r = risk.assess(db, a, ActionRequest("db.read", "db:customers:9999"), d, now=noon)
    assert "novel_resource" not in r.factors

    # A genuinely different family still scores as novel.
    r2 = risk.assess(db, a, ActionRequest("db.read", "db:salaries:1"), d, now=noon)
    assert "novel_resource" in r2.factors


def test_resource_family_generalization():
    from agentguard.utils import resource_family
    assert resource_family("db:customers:1042") == "db:customers:*"
    assert resource_family("http:crm/orders/98") == "http:crm/orders/*"
    assert resource_family("db:customers:*") == "db:customers:*"   # already a family
    assert resource_family("payment:stripe:refund") == "payment:stripe:refund"  # not an id


def test_loop_detection_flags_stuck_agent(db):
    """A run of the identical action+resource is a tool-call loop, not a spike."""
    a = _agent(db)
    led = AuditLedger(db)
    for _ in range(12):
        led.append(agent_id=a.id, agent_name="a", role_name="r", action_type="http.get",
                   resource="http:api/status", decision=Decision.ALLOW, reason="",
                   billable=True)
    prof = anomaly.profile(db, a.id, "http:api/status", "http.get")
    assert prof.loop_repeats >= 10


def test_flat_baseline_small_uptick_is_not_a_surge():
    """A steady low-volume agent must not trip a surge on a mild increase."""
    from agentguard.anomaly import _zscore_from_buckets as z
    assert z([2] + [1] * 12) == 0.0     # 1 -> 2 actions is not an anomaly
    assert z([3] + [1] * 12) == 0.0
    # A genuine multiple-and-magnitude jump is still caught.
    assert z([20] + [1] * 12) >= 3.0
    assert z([50] + [10] * 12) >= 3.0


def test_idle_or_batch_agent_has_no_surge_signal():
    """An agent with no recent baseline (e.g. a daily batch) isn't flagged."""
    from agentguard.anomaly import _zscore_from_buckets as z
    assert z([40] + [0] * 12) == 0.0
