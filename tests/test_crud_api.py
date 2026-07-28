"""Tests for CRUD API completion: pagination, update endpoints, filters."""



def _create_role(client, admin_headers, name="test-role", desc="test"):
    resp = client.post("/api/roles", json={"name": name, "description": desc}, headers=admin_headers)
    assert resp.status_code == 201, resp.text
    return resp.json()


def _create_agent(client, admin_headers, name="test-agent", role_id=None):
    if role_id is None:
        role_id = _create_role(client, admin_headers)["id"]
    resp = client.post("/api/agents", json={"name": name, "role_id": role_id, "owner": "tester"}, headers=admin_headers)
    assert resp.status_code == 201, resp.text
    return resp.json()


# --- Agent CRUD ---

def test_agent_update(client, admin_headers):
    agent = _create_agent(client, admin_headers)
    resp = client.put(f"/api/agents/{agent['id']}", json={"name": "updated-name", "quota": 500}, headers=admin_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["name"] == "updated-name"
    assert data["quota"] == 500


def test_agent_update_invalid_role(client, admin_headers):
    agent = _create_agent(client, admin_headers)
    resp = client.put(f"/api/agents/{agent['id']}", json={"role_id": 99999}, headers=admin_headers)
    assert resp.status_code == 400


def test_agent_update_not_found(client, admin_headers):
    resp = client.put("/api/agents/99999", json={"name": "x"}, headers=admin_headers)
    assert resp.status_code == 404


def test_agent_list_pagination(client, admin_headers):
    role = _create_role(client, admin_headers)
    for i in range(5):
        _create_agent(client, admin_headers, name=f"agent-{i}", role_id=role["id"])
    resp = client.get("/api/agents?limit=2&offset=0", headers=admin_headers)
    assert resp.status_code == 200
    assert len(resp.json()) == 2


def test_agent_list_status_filter(client, admin_headers):
    agent = _create_agent(client, admin_headers)
    client.post(f"/api/agents/{agent['id']}/status", json={"status": "suspended"}, headers=admin_headers)
    resp = client.get("/api/agents?status=suspended", headers=admin_headers)
    assert resp.status_code == 200
    assert all(a["status"] == "suspended" for a in resp.json())


def test_agent_delete(client, admin_headers):
    agent = _create_agent(client, admin_headers)
    resp = client.delete(f"/api/agents/{agent['id']}", headers=admin_headers)
    assert resp.status_code == 204
    resp = client.get(f"/api/agents/{agent['id']}", headers=admin_headers)
    assert resp.status_code == 404


# --- Role CRUD ---

def test_role_update(client, admin_headers):
    role = _create_role(client, admin_headers)
    resp = client.put(f"/api/roles/{role['id']}", json={"name": "renamed", "description": "new desc"}, headers=admin_headers)
    assert resp.status_code == 200
    assert resp.json()["name"] == "renamed"
    assert resp.json()["description"] == "new desc"


def test_role_update_conflict(client, admin_headers):
    _create_role(client, admin_headers, name="role-a")  # occupies the name
    r2 = _create_role(client, admin_headers, name="role-b")
    resp = client.put(f"/api/roles/{r2['id']}", json={"name": "role-a"}, headers=admin_headers)
    assert resp.status_code == 409


def test_role_update_not_found(client, admin_headers):
    resp = client.put("/api/roles/99999", json={"name": "x"}, headers=admin_headers)
    assert resp.status_code == 404


def test_role_pagination(client, admin_headers):
    for i in range(5):
        _create_role(client, admin_headers, name=f"role-p{i}")
    resp = client.get("/api/roles?limit=2&offset=0", headers=admin_headers)
    assert resp.status_code == 200
    assert len(resp.json()) == 2


def test_role_delete_with_agents_fails(client, admin_headers):
    role = _create_role(client, admin_headers, name="bound-role")
    _create_agent(client, admin_headers, role_id=role["id"])
    resp = client.delete(f"/api/roles/{role['id']}", headers=admin_headers)
    assert resp.status_code == 409


# --- Policy CRUD ---

def test_policy_create_and_update(client, admin_headers):
    role = _create_role(client, admin_headers, name="pol-role")
    resp = client.post(f"/api/roles/{role['id']}/policies", json={
        "effect": "allow", "resource": "db:*", "actions": ["read"], "priority": 5
    }, headers=admin_headers)
    assert resp.status_code == 201
    pid = resp.json()["id"]
    resp = client.put(f"/api/roles/{role['id']}/policies/{pid}", json={
        "effect": "deny", "resource": "db:secret:*", "actions": ["write"], "priority": 10
    }, headers=admin_headers)
    assert resp.status_code == 200
    assert resp.json()["effect"] == "deny"
    assert resp.json()["priority"] == 10


def test_policy_delete(client, admin_headers):
    role = _create_role(client, admin_headers, name="pol-del-role")
    resp = client.post(f"/api/roles/{role['id']}/policies", json={
        "effect": "allow", "resource": "*", "actions": ["*"]
    }, headers=admin_headers)
    pid = resp.json()["id"]
    resp = client.delete(f"/api/roles/{role['id']}/policies/{pid}", headers=admin_headers)
    assert resp.status_code == 204


# --- Connector CRUD ---

def test_connector_create_update_delete(client, admin_headers):
    resp = client.post("/api/connectors", json={
        "name": "test-conn", "base_url": "http://example.com", "auth_type": "bearer", "auth_secret": "secret123"
    }, headers=admin_headers)
    assert resp.status_code == 201
    cid = resp.json()["id"]
    assert resp.json()["has_secret"] is True

    resp = client.put(f"/api/connectors/{cid}", json={
        "name": "test-conn-updated", "base_url": "http://example.com/v2", "auth_type": "none", "auth_secret": ""
    }, headers=admin_headers)
    assert resp.status_code == 200
    assert resp.json()["name"] == "test-conn-updated"

    resp = client.delete(f"/api/connectors/{cid}", headers=admin_headers)
    assert resp.status_code == 204


def test_connector_pagination(client, admin_headers):
    for i in range(5):
        client.post("/api/connectors", json={
            "name": f"conn-{i}", "base_url": f"http://example{i}.com"
        }, headers=admin_headers)
    resp = client.get("/api/connectors?limit=2&offset=0", headers=admin_headers)
    assert resp.status_code == 200
    assert len(resp.json()) == 2


def test_connector_test_unreachable(client, admin_headers):
    resp = client.post("/api/connectors", json={
        "name": "unreachable", "base_url": "http://127.0.0.1:1"
    }, headers=admin_headers)
    cid = resp.json()["id"]
    resp = client.post(f"/api/connectors/{cid}/test", headers=admin_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["reachable"] is False
    assert data["error"]


# --- Audit filtering ---

def _admin_org(db):
    from sqlalchemy import select

    from agentops.models import User
    return db.scalar(select(User).where(User.email == "admin@agentops.local")).org_id


def test_audit_action_type_filter(client, admin_headers, db):
    from agentops.audit.ledger import AuditLedger
    from agentops.models import Decision
    oid = _admin_org(db)
    ledger = AuditLedger(db)
    ledger.append(agent_id=None, agent_name="a", role_name="r", action_type="db.read", resource="db:x", decision=Decision.ALLOW, reason="ok", org_id=oid)
    ledger.append(agent_id=None, agent_name="a", role_name="r", action_type="http.post", resource="http:y", decision=Decision.DENY, reason="blocked", org_id=oid)
    resp = client.get("/api/audit/records?action_type=db.read", headers=admin_headers)
    assert resp.status_code == 200
    records = resp.json()
    assert len(records) == 1
    assert all(r["action_type"] == "db.read" for r in records)


def test_audit_pagination(client, admin_headers, db):
    from agentops.audit.ledger import AuditLedger
    from agentops.models import Decision
    oid = _admin_org(db)
    ledger = AuditLedger(db)
    for i in range(10):
        ledger.append(agent_id=None, agent_name="a", role_name="r", action_type="act", resource=f"r:{i}", decision=Decision.ALLOW, reason="ok", org_id=oid)
    resp = client.get("/api/audit/records?limit=3&offset=0", headers=admin_headers)
    assert resp.status_code == 200
    assert len(resp.json()) == 3
