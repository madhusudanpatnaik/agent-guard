"""Regression tests for the defects found by the adversarial review.

Each test would FAIL against the pre-fix code and passes after the fix.
"""

import time

import httpx



# --- helpers ----------------------------------------------------------------

def _second_org(client, admin_headers, slug):
    org = client.post("/api/orgs", json={"name": slug.title(), "slug": slug},
                      headers=admin_headers).json()
    client.post(f"/api/orgs/{org['id']}/users",
                json={"email": f"{slug}@x.example", "password": "pass123456", "role": "admin"},
                headers=admin_headers)
    tok = client.post("/api/auth/login",
                      json={"email": f"{slug}@x.example", "password": "pass123456"}).json()
    return {"Authorization": f"Bearer {tok['access_token']}"}


def _role(client, h, name):
    return client.post("/api/roles", json={"name": name}, headers=h).json()["id"]


def _agent(client, h, rid, name):
    return client.post("/api/agents", json={"name": name, "role_id": rid}, headers=h).json()


# --- Finding 1/2: cross-tenant leak in analyzer (org_id scoping) ------------

def test_analysis_does_not_leak_across_same_named_roles(client, admin_headers):
    # Org A: role "billing" with denied traffic on a secret resource.
    rid_a = _role(client, admin_headers, "billing")
    agent_a = _agent(client, admin_headers, rid_a, "ABot")
    for i in range(3):
        client.post("/api/v1/gateway/authorize", headers={"X-API-Key": agent_a["api_key"]},
                    json={"action_type": "read", "resource": f"db:acme_secrets:{i}"})

    # Org B: a role with the SAME name "billing".
    hb = _second_org(client, admin_headers, "orgb")
    rid_b = _role(client, hb, "billing")

    # Org B's analysis + recommendations must NOT see Org A's resources.
    analysis = client.get(f"/api/roles/{rid_b}/analysis", headers=hb).json()
    recs = client.get(f"/api/roles/{rid_b}/recommendations", headers=hb).json()
    preview = client.post(f"/api/roles/{rid_b}/policies/preview", headers=hb,
                          json={"resource": "db:acme_secrets:*", "actions": ["read"]}).json()

    # analysis + recommendations must not surface Org A's resource strings.
    # (preview echoes the resource WE requested, so check its leak indicators
    # rather than its echoed request field.)
    assert "acme_secrets" not in (str(analysis) + str(recs))  # no cross-tenant leak
    assert analysis["denial_hotspots"] == []
    assert recs == []
    assert preview["would_allow"] == 0           # Org A's denials must not count
    assert preview["sample"] == []               # …and none replayed into the sample


# --- Finding: engine crash on malformed policy condition --------------------

def test_malformed_max_amount_does_not_crash_gateway(client, admin_headers):
    rid = _role(client, admin_headers, "badcond")
    client.post(f"/api/roles/{rid}/policies", headers=admin_headers, json={
        "effect": "allow", "resource": "payment:*", "actions": ["pay"],
        "conditions": {"max_amount": "abc"}})   # non-numeric
    agent = _agent(client, admin_headers, rid, "BCBot")
    r = client.post("/api/v1/gateway/authorize", headers={"X-API-Key": agent["api_key"]},
                    json={"action_type": "pay", "resource": "payment:x",
                          "metadata": {"amount": 100}})
    assert r.status_code == 200                       # no 500
    assert r.json()["decision"] == "require_approval"  # fails closed to human review


def test_malformed_rate_limit_fails_closed(client, admin_headers):
    rid = _role(client, admin_headers, "badrate")
    client.post(f"/api/roles/{rid}/policies", headers=admin_headers, json={
        "effect": "allow", "resource": "x:*", "actions": ["act"],
        "conditions": {"rate_limit": {"count": "five", "per_seconds": 60}}})
    agent = _agent(client, admin_headers, rid, "RLBot")
    r = client.post("/api/v1/gateway/authorize", headers={"X-API-Key": agent["api_key"]},
                    json={"action_type": "act", "resource": "x:1"})
    assert r.status_code == 200
    assert r.json()["decision"] == "deny"


# --- Finding: ReDoS in custom detectors -------------------------------------

def test_catastrophic_detector_pattern_is_rejected(client, admin_headers):
    # A classic exponential-backtracking pattern must be refused at create time.
    r = client.post("/api/detectors", headers=admin_headers,
                    json={"name": "evil", "pattern": r"(a+)+$", "severity": "high"})
    assert r.status_code == 400
    assert "backtracking" in r.json()["detail"].lower() or "slow" in r.json()["detail"].lower()


def test_detector_test_endpoint_bounds_runtime(client, admin_headers):
    # /test with a catastrophic pattern must return quickly, not hang the worker.
    start = time.monotonic()
    r = client.post("/api/detectors/test", headers=admin_headers,
                    json={"pattern": r"(a+)+$", "sample": "a" * 40 + "X"})
    elapsed = time.monotonic() - start
    assert elapsed < 5.0                    # bounded, did not hang
    body = r.json()
    assert body["valid"] is False and "timed out" in (body["error"] or "").lower()


def test_safe_custom_detector_still_works(client, admin_headers):
    r = client.post("/api/detectors", headers=admin_headers,
                    json={"name": "acme", "pattern": r"ACME-[0-9A-F]{8}", "severity": "critical"})
    assert r.status_code == 201


# --- Finding: reputation dlp_incidents billable filter ----------------------

def test_reputation_ignores_upstream_response_dlp(db):
    from agentguard.audit.ledger import AuditLedger
    from agentguard.models import Agent, Decision, Role
    from agentguard.reputation import compute
    role = Role(name="rr")
    db.add(role)
    db.flush()
    a = Agent(name="rrb", role_id=role.id, api_key_hash="hh", api_key_prefix="pp")
    db.add(a)
    db.commit()
    db.refresh(a)
    led = AuditLedger(db)
    # 4 clean BILLABLE request rows...
    for i in range(4):
        led.append(agent_id=a.id, agent_name="rrb", role_name="rr", action_type="http.get",
                   resource=f"h:{i}", decision=Decision.ALLOW, reason="", billable=True)
    # ...and 4 NON-billable .result rows whose UPSTREAM response carried PII.
    for i in range(4):
        led.append(agent_id=a.id, agent_name="rrb", role_name="rr",
                   action_type="http.get.result", resource=f"h:{i}",
                   decision=Decision.ALLOW, reason="", billable=False,
                   dlp_findings=[{"detector": "us_ssn", "severity": "high",
                                  "count": 1, "sample": "x", "path": "$"}])
    rep = compute(db, a)
    # The agent's own payloads were clean -> no dlp_rate penalty, stays trusted.
    assert not any("dlp_rate" in f for f in rep.factors)
    assert rep.band == "trusted"


# --- Finding: approval not burned when post-claim authorization denies -------

def test_approval_restored_when_containment_blocks_execution(client, admin_headers, monkeypatch):
    # Enforced refund needing approval; approve it; then contain the org so the
    # follow-up execute is denied — the approval must survive (not be consumed).
    UPSTREAM_KEY = "k"
    import agentguard.gateway_service as gs

    def _handler(request):
        return httpx.Response(200, json={"ok": True})
    real_client = httpx.Client
    monkeypatch.setattr(gs.httpx, "Client",
                        lambda *a, **k: real_client(*a, transport=httpx.MockTransport(_handler)))

    client.post("/api/connectors", headers=admin_headers, json={
        "name": "pay", "base_url": "http://up.local", "auth_type": "bearer",
        "auth_secret": UPSTREAM_KEY})
    rid = _role(client, admin_headers, "rf")
    client.post(f"/api/roles/{rid}/policies", headers=admin_headers, json={
        "name": "refund", "effect": "allow", "resource": "http:pay/refunds",
        "actions": ["http.post"], "conditions": {"require_approval_over": 500}})
    agent = _agent(client, admin_headers, rid, "RFBot")
    key = {"X-API-Key": agent["api_key"]}

    first = client.post("/api/v1/gateway/execute", headers=key, json={
        "connector": "pay", "method": "POST", "path": "/refunds",
        "body": {"amount": 2000}, "metadata": {"amount": 2000}}).json()
    assert first["decision"] == "require_approval"
    aid = first["approval_id"]
    client.post(f"/api/approvals/{aid}/resolve", headers=admin_headers,
                json={"approve": True, "note": "ok"})

    # Contain the org so the approved execute is force-denied.
    client.post("/api/orgs/containment", headers=admin_headers,
                json={"contained": True, "reason": "freeze"})
    blocked = client.post("/api/v1/gateway/execute", headers=key, json={
        "connector": "pay", "method": "POST", "path": "/refunds",
        "body": {"amount": 2000}, "metadata": {"amount": 2000}, "approval_id": aid}).json()
    assert blocked["executed"] is False

    # Lift containment; the SAME approval should still work (was not burned).
    client.post("/api/orgs/containment", headers=admin_headers, json={"contained": False})
    done = client.post("/api/v1/gateway/execute", headers=key, json={
        "connector": "pay", "method": "POST", "path": "/refunds",
        "body": {"amount": 2000}, "metadata": {"amount": 2000}, "approval_id": aid}).json()
    assert done["executed"] is True


# --- Finding: falsy body dropped on execute ---------------------------------

def test_empty_object_body_is_transmitted(client, admin_headers, monkeypatch):
    import agentguard.gateway_service as gs
    captured = {}

    def _handler(request):
        captured["content"] = request.content
        return httpx.Response(200, json={"ok": True})
    real_client = httpx.Client
    monkeypatch.setattr(gs.httpx, "Client",
                        lambda *a, **k: real_client(*a, transport=httpx.MockTransport(_handler)))

    client.post("/api/connectors", headers=admin_headers, json={
        "name": "up", "base_url": "http://up.local", "auth_type": "none"})
    rid = _role(client, admin_headers, "eb")
    client.post(f"/api/roles/{rid}/policies", headers=admin_headers, json={
        "effect": "allow", "resource": "http:up/**", "actions": ["http.post"]})
    agent = _agent(client, admin_headers, rid, "EBBot")
    r = client.post("/api/v1/gateway/execute", headers={"X-API-Key": agent["api_key"]},
                    json={"connector": "up", "method": "POST", "path": "/x", "body": {}}).json()
    assert r["executed"] is True
    # The empty-object body must actually be sent, not dropped to no-body.
    assert captured["content"] == b"{}"
