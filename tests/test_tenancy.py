"""Multi-tenancy isolation tests — prove org A cannot see or use org B's data.

Org A is the bootstrap "default" org (the superadmin). Org B is created by the
superadmin with its own (non-super) admin. Every resource boundary is exercised.
"""

import pytest


def _login(client, email, password):
    r = client.post("/api/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture
def org_a(client):
    # Bootstrap superadmin, in the "default" org.
    return _login(client, "admin@agentops.local", "admin")


@pytest.fixture
def org_b(client, org_a):
    org = client.post("/api/orgs", json={"name": "Beta", "slug": "beta"},
                      headers=org_a).json()
    client.post(f"/api/orgs/{org['id']}/users",
                json={"email": "admin@beta.example", "password": "betapass123", "role": "admin"},
                headers=org_a)
    return {"id": org["id"], "headers": _login(client, "admin@beta.example", "betapass123")}


def _key(agent):
    return {"X-API-Key": agent["api_key"]}


# --- resource isolation -----------------------------------------------------

def test_roles_are_isolated(client, org_a, org_b):
    ra = client.post("/api/roles", json={"name": "secret-a"}, headers=org_a).json()
    b_names = [r["name"] for r in client.get("/api/roles", headers=org_b["headers"]).json()]
    assert "secret-a" not in b_names
    assert client.get(f"/api/roles/{ra['id']}", headers=org_b["headers"]).status_code == 404
    assert client.delete(f"/api/roles/{ra['id']}", headers=org_b["headers"]).status_code == 404
    # …but org A still owns it.
    assert client.get(f"/api/roles/{ra['id']}", headers=org_a).status_code == 200


def test_connector_names_reusable_across_orgs(client, org_a, org_b):
    a = client.post("/api/connectors",
                    json={"name": "crm", "base_url": "http://a", "auth_type": "none"}, headers=org_a)
    b = client.post("/api/connectors",
                    json={"name": "crm", "base_url": "http://b", "auth_type": "none"},
                    headers=org_b["headers"])
    assert a.status_code == 201 and b.status_code == 201  # same name, different tenant
    a_crm = [c for c in client.get("/api/connectors", headers=org_a).json() if c["name"] == "crm"]
    b_crm = [c for c in client.get("/api/connectors", headers=org_b["headers"]).json()
             if c["name"] == "crm"]
    assert [c["base_url"] for c in a_crm] == ["http://a"]
    assert [c["base_url"] for c in b_crm] == ["http://b"]


def test_agent_cannot_be_bound_to_other_orgs_role(client, org_a, org_b):
    ra = client.post("/api/roles", json={"name": "role-a"}, headers=org_a).json()
    # org B tries to create an agent using org A's role id.
    r = client.post("/api/agents", json={"name": "x", "role_id": ra["id"]},
                    headers=org_b["headers"])
    assert r.status_code == 400


# --- the critical boundary: the gateway ------------------------------------

def _agent_with_policy(client, headers, *, role, resource, actions, approval=False):
    rid = client.post("/api/roles", json={"name": role}, headers=headers).json()["id"]
    client.post(f"/api/roles/{rid}/policies", headers=headers, json={
        "effect": "allow", "resource": resource, "actions": actions,
        "require_approval": approval})
    return client.post("/api/agents", json={"name": f"agent-{role}", "role_id": rid},
                       headers=headers).json()


def test_agent_cannot_use_another_orgs_connector(client, org_a, org_b):
    # Connector "payA" exists ONLY in org A.
    client.post("/api/connectors",
                json={"name": "payA", "base_url": "http://a", "auth_type": "none"}, headers=org_a)
    # An org B agent, even with a matching policy, cannot resolve it.
    agent_b = _agent_with_policy(client, org_b["headers"], role="rb",
                                 resource="http:payA/**", actions=["http.get"])
    r = client.post("/api/v1/gateway/execute", headers=_key(agent_b),
                    json={"connector": "payA", "method": "GET", "path": "/x"})
    assert r.status_code == 400
    assert "unknown or disabled connector" in r.json()["detail"]


def test_audit_records_are_isolated(client, org_a, org_b):
    agent_a = _agent_with_policy(client, org_a, role="ra", resource="db:x", actions=["read"])
    client.post("/api/v1/gateway/authorize", headers=_key(agent_a),
                json={"action_type": "read", "resource": "db:x"})
    # org B sees none of org A's audit records.
    assert client.get("/api/audit/records", headers=org_b["headers"]).json() == []
    a_records = client.get("/api/audit/records", headers=org_a).json()
    assert any(r["resource"] == "db:x" for r in a_records)
    # export is scoped too.
    assert client.get("/api/audit/export?fmt=jsonl", headers=org_b["headers"]).text.strip() == ""


def test_approvals_are_isolated(client, org_a, org_b):
    agent_a = _agent_with_policy(client, org_a, role="ra", resource="pay:*",
                                 actions=["pay.do"], approval=True)
    res = client.post("/api/v1/gateway/authorize", headers=_key(agent_a),
                      json={"action_type": "pay.do", "resource": "pay:1"}).json()
    aid = res["approval_id"]
    assert aid
    assert client.get("/api/approvals", headers=org_b["headers"]).json() == []
    assert client.post(f"/api/approvals/{aid}/resolve", json={"approve": True},
                       headers=org_b["headers"]).status_code == 404
    assert client.post(f"/api/approvals/{aid}/resolve", json={"approve": True},
                       headers=org_a).status_code == 200


def test_dashboard_is_scoped(client, org_a, org_b):
    rid = client.post("/api/roles", json={"name": "r"}, headers=org_a).json()["id"]
    for i in range(2):
        client.post("/api/agents", json={"name": f"a{i}", "role_id": rid}, headers=org_a)
    assert client.get("/api/dashboard/stats", headers=org_b["headers"]).json()["agents_total"] == 0
    assert client.get("/api/dashboard/stats", headers=org_a).json()["agents_total"] >= 2


# --- org administration -----------------------------------------------------

def test_only_superadmin_manages_orgs(client, org_b):
    assert client.get("/api/orgs", headers=org_b["headers"]).status_code == 403
    assert client.post("/api/orgs", json={"name": "X", "slug": "xx"},
                       headers=org_b["headers"]).status_code == 403


def test_provisioned_user_is_scoped_to_its_org(client, org_a, org_b):
    me = client.get("/api/auth/me", headers=org_b["headers"]).json()
    assert me["org_id"] == org_b["id"]
    assert me["is_superadmin"] is False


def test_global_ledger_endpoints_are_superadmin_only(client, org_a, org_b):
    # Superadmin (org A bootstrap) can see global chain integrity…
    assert client.get("/api/audit/verify", headers=org_a).status_code == 200
    assert client.get("/api/audit/head", headers=org_a).status_code == 200
    # …a tenant admin cannot (would leak global chain length/head).
    assert client.get("/api/audit/verify", headers=org_b["headers"]).status_code == 403
    assert client.get("/api/audit/head", headers=org_b["headers"]).status_code == 403
