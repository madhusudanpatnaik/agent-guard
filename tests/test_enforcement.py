"""Tests for ENFORCED mode: the plane executes upstream calls on the agent's behalf.

The upstream is simulated with an httpx MockTransport so the real code path in
``execute_action`` (credential injection, policy gate, response-side DLP) runs
end-to-end without a live server. The mock rejects any request that does not carry
the upstream key — so a passing 200 proves the plane injected the credential the
agent never possessed.
"""

import json

import httpx
import pytest

from agentguard import gateway_service

UPSTREAM_KEY = "upstream-test-key-123"


def _upstream_handler(request: httpx.Request) -> httpx.Response:
    authorized = (
        request.headers.get("x-api-key") == UPSTREAM_KEY
        or request.headers.get("authorization") == f"Bearer {UPSTREAM_KEY}"
    )
    if not authorized:
        return httpx.Response(401, json={"detail": "missing/invalid upstream key"})
    if request.url.path.startswith("/customers/"):
        return httpx.Response(200, json={
            "id": 1042, "name": "Dana Reyes", "tier": "vip",
            "ssn": "452-11-9832", "card_number": "4242 4242 4242 4242",
        })
    if request.url.path == "/refunds":
        body = json.loads(request.content or b"{}")
        return httpx.Response(200, json={
            "refund_id": "re_1", "status": "succeeded", "amount": body.get("amount")})
    return httpx.Response(404, json={"detail": "not found"})


@pytest.fixture
def mock_upstream(monkeypatch):
    real_client = httpx.Client

    def factory(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(_upstream_handler)
        return real_client(*args, **kwargs)

    monkeypatch.setattr(gateway_service.httpx, "Client", factory)


@pytest.fixture
def enforced(client, admin_headers):
    # Connectors (plane holds the credential).
    client.post("/api/connectors", headers=admin_headers, json={
        "name": "crm", "base_url": "http://upstream.local", "auth_type": "header",
        "auth_header_name": "X-API-Key", "auth_secret": UPSTREAM_KEY})
    client.post("/api/connectors", headers=admin_headers, json={
        "name": "payments", "base_url": "http://upstream.local", "auth_type": "bearer",
        "auth_secret": UPSTREAM_KEY})

    role = client.post("/api/roles", headers=admin_headers,
                       json={"name": "ops"}).json()
    rid = role["id"]
    client.post(f"/api/roles/{rid}/policies", headers=admin_headers, json={
        "name": "crm-read", "effect": "allow", "resource": "http:crm/customers/*",
        "actions": ["http.get"]})
    client.post(f"/api/roles/{rid}/policies", headers=admin_headers, json={
        "name": "refunds", "effect": "allow", "resource": "http:payments/refunds",
        "actions": ["http.post"], "conditions": {"require_approval_over": 500}})

    agent = client.post("/api/agents", headers=admin_headers,
                        json={"name": "OpsBot", "role_id": rid}).json()
    return {"key_headers": {"X-API-Key": agent["api_key"]}, "admin": admin_headers}


def _execute(client, key_headers, **body):
    return client.post("/api/v1/gateway/execute", headers=key_headers, json=body)


def test_connector_secret_is_never_returned(client, admin_headers, enforced):
    conns = client.get("/api/connectors", headers=admin_headers).json()
    assert conns
    for c in conns:
        assert "auth_secret" not in c
        assert "auth_secret_encrypted" not in c
        assert c["has_secret"] is True


def test_allowed_call_executes_and_injects_credential(client, enforced, mock_upstream):
    r = _execute(client, enforced["key_headers"], connector="crm", method="GET",
                 path="/customers/1042")
    body = r.json()
    # A 200 proves the plane injected the key the agent never had.
    assert body["executed"] is True
    assert body["status_code"] == 200


def test_response_pii_is_dlp_redacted_before_the_agent_sees_it(client, enforced, mock_upstream):
    r = _execute(client, enforced["key_headers"], connector="crm", method="GET",
                 path="/customers/1042").json()
    returned = json.dumps(r["response_body"])
    assert "452-11-9832" not in returned          # SSN redacted
    assert "4242 4242 4242 4242" not in returned   # card redacted
    detectors = {f["detector"] for f in r["response_dlp_findings"]}
    assert "us_ssn" in detectors


def test_disallowed_method_is_refused_upstream_never_called(client, enforced, mock_upstream):
    r = _execute(client, enforced["key_headers"], connector="crm", method="POST",
                 path="/customers/1042", body={"tier": "hacked"}).json()
    assert r["executed"] is False
    assert r["decision"] == "deny"
    assert r["status_code"] is None


def test_refund_under_threshold_executes(client, enforced, mock_upstream):
    r = _execute(client, enforced["key_headers"], connector="payments", method="POST",
                 path="/refunds", body={"invoice": "i1", "amount": 250},
                 metadata={"amount": 250}).json()
    assert r["executed"] is True
    assert r["response_body"]["status"] == "succeeded"


def test_over_threshold_requires_approval_then_executes(client, enforced, mock_upstream):
    first = _execute(client, enforced["key_headers"], connector="payments", method="POST",
                     path="/refunds", body={"invoice": "i2", "amount": 2000},
                     metadata={"amount": 2000}).json()
    assert first["executed"] is False
    assert first["decision"] == "require_approval"
    approval_id = first["approval_id"]
    assert approval_id

    client.post(f"/api/approvals/{approval_id}/resolve", headers=enforced["admin"],
                json={"approve": True, "note": "ok"})

    second = _execute(client, enforced["key_headers"], connector="payments", method="POST",
                      path="/refunds", body={"invoice": "i2", "amount": 2000},
                      metadata={"amount": 2000}, approval_id=approval_id).json()
    assert second["executed"] is True
    assert second["response_body"]["status"] == "succeeded"

    # Single-use: replaying the SAME approval must NOT execute again.
    replay = _execute(client, enforced["key_headers"], connector="payments", method="POST",
                      path="/refunds", body={"invoice": "i2", "amount": 2000},
                      metadata={"amount": 2000}, approval_id=approval_id).json()
    assert replay["executed"] is False
    assert replay["decision"] == "require_approval"


def test_approval_claim_is_atomic_single_use(db):
    # The atomic compare-and-swap consumes an approval exactly once — the race-safe
    # primitive behind single-use approvals.
    from agentguard.gateway_service import _claim_approval
    from agentguard.models import Agent, Approval, ApprovalStatus, Role
    role = Role(name="r")
    db.add(role)
    db.flush()
    agent = Agent(name="a", role_id=role.id, api_key_hash="h", api_key_prefix="p")
    db.add(agent)
    db.flush()
    appr = Approval(agent_id=agent.id, resource="pay:1", action_type="pay.do",
                    status=ApprovalStatus.APPROVED)
    db.add(appr)
    db.commit()
    db.refresh(appr)

    first = _claim_approval(db, appr.id, agent, "pay:1", "pay.do")
    second = _claim_approval(db, appr.id, agent, "pay:1", "pay.do")
    assert first is True
    assert second is False   # already consumed — a concurrent second caller loses
    db.refresh(appr)
    assert appr.status == ApprovalStatus.USED


def test_absolute_url_path_is_rejected(client, enforced, mock_upstream):
    # An agent must not be able to pivot the connector to an arbitrary host.
    r = _execute(client, enforced["key_headers"], connector="crm", method="GET",
                 path="http://evil.example/steal")
    assert r.status_code == 400


def test_path_traversal_is_rejected(client, enforced, mock_upstream):
    # `/customers/..` would be policy-checked as one path but hit another — reject it.
    r = _execute(client, enforced["key_headers"], connector="crm", method="GET",
                 path="/customers/../admin")
    assert r.status_code == 400
