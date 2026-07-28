"""Tests for policy change history + rollback."""


def _role(client, admin_headers, name="hist"):
    return client.post("/api/roles", json={"name": name}, headers=admin_headers).json()["id"]


def _add(client, admin_headers, rid, **kw):
    body = {"effect": "allow", "resource": "db:a", "actions": ["read"], **kw}
    return client.post(f"/api/roles/{rid}/policies", json=body, headers=admin_headers).json()


def _versions(client, admin_headers, rid, pid):
    return client.get(f"/api/roles/{rid}/policies/{pid}/versions", headers=admin_headers).json()


def test_create_records_version_1(client, admin_headers):
    rid = _role(client, admin_headers)
    pol = _add(client, admin_headers, rid)
    vers = _versions(client, admin_headers, rid, pol["id"])
    assert len(vers) == 1
    assert vers[0]["version"] == 1
    assert vers[0]["action"] == "create"
    assert vers[0]["changed_by"] == "admin@agentops.local"
    assert vers[0]["snapshot"]["resource"] == "db:a"


def test_updates_accumulate_versions(client, admin_headers):
    rid = _role(client, admin_headers)
    pol = _add(client, admin_headers, rid)
    client.put(f"/api/roles/{rid}/policies/{pol['id']}", headers=admin_headers,
               json={"effect": "allow", "resource": "db:b", "actions": ["read"]})
    client.put(f"/api/roles/{rid}/policies/{pol['id']}", headers=admin_headers,
               json={"effect": "deny", "resource": "db:c", "actions": ["write"]})
    vers = _versions(client, admin_headers, rid, pol["id"])
    assert [v["version"] for v in vers] == [3, 2, 1]     # newest first
    assert vers[0]["snapshot"]["resource"] == "db:c"
    assert vers[0]["snapshot"]["effect"] == "deny"


def test_rollback_restores_prior_state(client, admin_headers):
    rid = _role(client, admin_headers)
    pol = _add(client, admin_headers, rid, resource="db:original", actions=["read"])
    # Change it to something wrong.
    client.put(f"/api/roles/{rid}/policies/{pol['id']}", headers=admin_headers,
               json={"effect": "allow", "resource": "db:BROKEN", "actions": ["*"]})
    # Roll back to version 1.
    r = client.post(f"/api/roles/{rid}/policies/{pol['id']}/rollback/1", headers=admin_headers)
    assert r.status_code == 200
    restored = r.json()
    assert restored["resource"] == "db:original"
    assert restored["actions"] == ["read"]
    # Rollback itself is recorded as a new version.
    vers = _versions(client, admin_headers, rid, pol["id"])
    assert vers[0]["action"] == "rollback"
    assert vers[0]["version"] == 3


def test_rollback_actually_changes_enforcement(client, admin_headers):
    rid = _role(client, admin_headers)
    pol = _add(client, admin_headers, rid, resource="db:x", actions=["read"])
    agent = client.post("/api/agents", json={"name": "HB", "role_id": rid},
                        headers=admin_headers).json()
    key = {"X-API-Key": agent["api_key"]}

    def decide():
        return client.post("/api/v1/gateway/authorize", headers=key,
                           json={"action_type": "read", "resource": "db:x"}).json()["decision"]

    assert decide() == "allow"
    # Break it (resource no longer matches).
    client.put(f"/api/roles/{rid}/policies/{pol['id']}", headers=admin_headers,
               json={"effect": "allow", "resource": "db:other", "actions": ["read"]})
    assert decide() == "deny"
    # Roll back -> enforcement is restored.
    client.post(f"/api/roles/{rid}/policies/{pol['id']}/rollback/1", headers=admin_headers)
    assert decide() == "allow"


def test_delete_records_final_snapshot(client, admin_headers):
    rid = _role(client, admin_headers)
    pol = _add(client, admin_headers, rid)
    client.delete(f"/api/roles/{rid}/policies/{pol['id']}", headers=admin_headers)
    vers = _versions(client, admin_headers, rid, pol["id"])   # history survives deletion
    assert any(v["action"] == "delete" for v in vers)


def test_rollback_to_missing_version_404(client, admin_headers):
    rid = _role(client, admin_headers)
    pol = _add(client, admin_headers, rid)
    r = client.post(f"/api/roles/{rid}/policies/{pol['id']}/rollback/99", headers=admin_headers)
    assert r.status_code == 404


def test_history_is_tenant_scoped(client, admin_headers):
    rid = _role(client, admin_headers)
    pol = _add(client, admin_headers, rid)
    org = client.post("/api/orgs", json={"name": "Hist", "slug": "hist"},
                      headers=admin_headers).json()
    client.post(f"/api/orgs/{org['id']}/users",
                json={"email": "h@h.example", "password": "hpass12345", "role": "admin"},
                headers=admin_headers)
    tok = client.post("/api/auth/login",
                      json={"email": "h@h.example", "password": "hpass12345"}).json()
    hh = {"Authorization": f"Bearer {tok['access_token']}"}
    # Other tenant can't see the role at all (404 on the role guard).
    assert client.get(f"/api/roles/{rid}/policies/{pol['id']}/versions",
                      headers=hh).status_code == 404


def test_concurrent_version_allocation_is_unique(db):
    """Two version records for the same policy can't collide on version number."""
    from agentops.models import Policy, PolicyVersion, Role
    from agentops.policy import history
    from sqlalchemy import select
    role = Role(name="cc")
    db.add(role)
    db.flush()
    p = Policy(role_id=role.id, effect="allow", resource="db:x", actions=["read"])
    db.add(p)
    db.flush()
    # Record several versions; each must get a distinct number under the unique
    # constraint (the savepoint-retry allocates the next free version).
    for _ in range(5):
        history.record(db, p, "update", "a@b", org_id=None)
    db.commit()
    versions = list(db.scalars(select(PolicyVersion.version).where(
        PolicyVersion.policy_id == p.id)))
    assert sorted(versions) == [1, 2, 3, 4, 5]
    assert len(versions) == len(set(versions))   # no duplicates
