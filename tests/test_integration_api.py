"""Full-stack integration test exercising the HTTP API end-to-end."""

import pytest


@pytest.fixture
def setup(client, admin_headers):
    """Create a role with policies and a registered agent; return context."""
    role = client.post(
        "/api/roles", headers=admin_headers,
        json={"name": "support", "description": "support agent"},
    ).json()
    rid = role["id"]

    def add_policy(**kw):
        r = client.post(f"/api/roles/{rid}/policies", headers=admin_headers, json=kw)
        assert r.status_code == 201, r.text
        return r.json()

    add_policy(name="read-crm", effect="allow", resource="db:customers:*",
               actions=["read"], priority=10)
    add_policy(name="no-writes", effect="deny", resource="db:customers:*",
               actions=["write"], priority=100)
    add_policy(name="refunds", effect="allow", resource="payment:stripe:refund",
               actions=["payment.refund"], conditions={"require_approval_over": 500})
    add_policy(name="partner-webhook", effect="allow", resource="http:api.partner.com/**",
               actions=["http.post"])

    agent = client.post(
        "/api/agents", headers=admin_headers,
        json={"name": "SupportBot", "role_id": rid, "owner": "support@x.com"},
    ).json()
    return {"role_id": rid, "agent": agent, "key_headers": {"X-API-Key": agent["api_key"]}}


def authorize(client, key_headers, **body):
    return client.post("/api/v1/gateway/authorize", headers=key_headers, json=body)


def test_login_and_me(client, admin_headers):
    r = client.get("/api/auth/me", headers=admin_headers)
    assert r.status_code == 200
    assert r.json()["role"] == "admin"


def test_agent_key_is_returned_once(setup):
    assert setup["agent"]["api_key"].startswith("agentguard_sk_")


def test_allow_decision(client, setup):
    r = authorize(client, setup["key_headers"], action_type="read",
                  resource="db:customers:1042", payload={"q": "select 1"})
    assert r.status_code == 200
    body = r.json()
    assert body["decision"] == "allow"
    assert body["audit_hash"]


def test_deny_decision(client, setup):
    r = authorize(client, setup["key_headers"], action_type="write",
                  resource="db:customers:1042", payload={"set": {"x": 1}})
    assert r.json()["decision"] == "deny"


def test_dlp_blocks_egress_of_secret(client, setup):
    r = authorize(
        client, setup["key_headers"], action_type="http.post",
        resource="http:api.partner.com/webhook",
        payload={"body": "AKIAIOSFODNN7EXAMPLE and ssn 452-11-9832"},
    )
    body = r.json()
    assert body["decision"] == "deny"
    assert any(f["detector"] == "aws_access_key_id" for f in body["dlp_findings"])


def test_approval_workflow(client, admin_headers, setup):
    # Over-threshold refund -> require approval.
    r = authorize(client, setup["key_headers"], action_type="payment.refund",
                  resource="payment:stripe:refund", metadata={"amount": 900})
    body = r.json()
    assert body["decision"] == "require_approval"
    approval_id = body["approval_id"]
    assert approval_id

    pending = client.get("/api/approvals?status_filter=pending", headers=admin_headers).json()
    assert any(a["id"] == approval_id for a in pending)

    resolved = client.post(
        f"/api/approvals/{approval_id}/resolve", headers=admin_headers,
        json={"approve": True, "note": "ok"},
    ).json()
    assert resolved["status"] == "approved"

    polled = client.get(
        f"/api/v1/gateway/approvals/{approval_id}", headers=setup["key_headers"]
    ).json()
    assert polled["status"] == "approved"


def test_suspended_agent_is_rejected(client, admin_headers, setup):
    aid = setup["agent"]["id"]
    client.post(f"/api/agents/{aid}/status", headers=admin_headers,
                json={"status": "suspended"})
    r = authorize(client, setup["key_headers"], action_type="read", resource="db:customers:1")
    assert r.status_code == 403


def test_ledger_integrity_and_stats(client, admin_headers, setup):
    # Generate a spread of decisions.
    authorize(client, setup["key_headers"], action_type="read", resource="db:customers:1")
    authorize(client, setup["key_headers"], action_type="write", resource="db:customers:1")
    authorize(client, setup["key_headers"], action_type="http.post",
              resource="http:api.partner.com/x", payload={"k": "AKIAIOSFODNN7EXAMPLE"})

    verify = client.get("/api/audit/verify", headers=admin_headers).json()
    assert verify["valid"] is True
    assert verify["length"] >= 3

    stats = client.get("/api/dashboard/stats", headers=admin_headers).json()
    assert stats["decisions_total"] >= 3
    assert stats["decisions_denied"] >= 2
    assert stats["dlp_incidents"] >= 1
    assert stats["ledger_valid"] is True


def test_unauthorized_without_key(client):
    r = client.post("/api/v1/gateway/authorize",
                    json={"action_type": "read", "resource": "db:x"})
    assert r.status_code == 401


def test_default_deny_for_unknown_resource(client, setup):
    r = authorize(client, setup["key_headers"], action_type="read", resource="db:secrets:1")
    assert r.json()["decision"] == "deny"
    assert "default-deny" in r.json()["reason"].lower()
