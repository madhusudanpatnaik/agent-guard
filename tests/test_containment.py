"""Tests for the org-level emergency kill switch (containment mode)."""



def _agent_with_allow(client, admin_headers):
    role = client.post("/api/roles", json={"name": "ops"}, headers=admin_headers).json()
    rid = role["id"]
    client.post(f"/api/roles/{rid}/policies", headers=admin_headers, json={
        "effect": "allow", "resource": "db:**", "actions": ["read"]})
    return client.post("/api/agents", json={"name": "OpsBot", "role_id": rid},
                       headers=admin_headers).json()


def _authorize(client, key):
    return client.post("/api/v1/gateway/authorize", headers={"X-API-Key": key},
                       json={"action_type": "read", "resource": "db:customers:1"})


def test_containment_denies_all_then_resume_restores(client, admin_headers):
    agent = _agent_with_allow(client, admin_headers)
    key = agent["api_key"]
    # Baseline: allowed.
    assert _authorize(client, key).json()["decision"] == "allow"

    # Freeze the fleet.
    r = client.post("/api/orgs/containment", headers=admin_headers,
                    json={"contained": True, "reason": "incident #42"})
    assert r.status_code == 200
    assert r.json()["contained"] is True

    # Now every action is denied, regardless of policy.
    denied = _authorize(client, key).json()
    assert denied["decision"] == "deny"
    assert "contained" in denied["reason"].lower()
    assert "incident #42" in denied["reason"]

    # Resume.
    r = client.post("/api/orgs/containment", headers=admin_headers,
                    json={"contained": False})
    assert r.json()["contained"] is False
    assert _authorize(client, key).json()["decision"] == "allow"


def test_containment_is_recorded_in_ledger(client, admin_headers):
    client.post("/api/orgs/containment", headers=admin_headers,
                json={"contained": True, "reason": "drill"})
    records = client.get("/api/audit/records?action_type=org.contain",
                         headers=admin_headers).json()
    assert any(r["action_type"] == "org.contain" for r in records)


def test_containment_is_per_tenant(client, admin_headers):
    # Set up a second org.
    org = client.post("/api/orgs", json={"name": "Beta", "slug": "beta"},
                      headers=admin_headers).json()
    client.post(f"/api/orgs/{org['id']}/users",
                json={"email": "admin@beta.example", "password": "betapass123", "role": "admin"},
                headers=admin_headers)
    b = client.post("/api/auth/login",
                    json={"email": "admin@beta.example", "password": "betapass123"}).json()
    b_headers = {"Authorization": f"Bearer {b['access_token']}"}
    b_agent = _agent_with_allow(client, b_headers)

    # Contain org A (the default org) only.
    client.post("/api/orgs/containment", headers=admin_headers,
                json={"contained": True, "reason": "A only"})

    # Org B is unaffected.
    assert _authorize(client, b_agent["api_key"]).json()["decision"] == "allow"


def test_superadmin_can_contain_any_org(client, admin_headers):
    org = client.post("/api/orgs", json={"name": "Gamma", "slug": "gamma"},
                      headers=admin_headers).json()
    client.post(f"/api/orgs/{org['id']}/users",
                json={"email": "admin@gamma.example", "password": "gammapass123", "role": "admin"},
                headers=admin_headers)
    g = client.post("/api/auth/login",
                    json={"email": "admin@gamma.example", "password": "gammapass123"}).json()
    g_headers = {"Authorization": f"Bearer {g['access_token']}"}
    g_agent = _agent_with_allow(client, g_headers)

    # Superadmin (default org bootstrap) contains org Gamma cross-tenant.
    r = client.post(f"/api/orgs/{org['id']}/containment", headers=admin_headers,
                    json={"contained": True, "reason": "platform incident"})
    assert r.status_code == 200
    assert _authorize(client, g_agent["api_key"]).json()["decision"] == "deny"


def test_timed_containment_auto_expires(client, admin_headers):
    agent = _agent_with_allow(client, admin_headers)
    key = agent["api_key"]
    # Freeze for a window, then rewind contained_until into the past.
    r = client.post("/api/orgs/containment", headers=admin_headers,
                    json={"contained": True, "reason": "brief", "duration_minutes": 30})
    assert r.status_code == 200
    assert r.json()["contained_until"] is not None
    assert _authorize(client, key).json()["decision"] == "deny"  # frozen now

    # Simulate the window elapsing.
    from datetime import datetime, timedelta, timezone
    from sqlalchemy import select
    from agentops.database import SessionLocal
    from agentops.models import Organization
    with SessionLocal() as db:
        org = db.scalar(select(Organization).where(Organization.slug == "default"))
        org.contained_until = datetime.now(timezone.utc) - timedelta(minutes=1)
        db.commit()

    # Next request auto-lifts the freeze (lazy expiry) and is allowed.
    assert _authorize(client, key).json()["decision"] == "allow"
    # The org now reports itself resumed.
    orgs = client.get("/api/orgs", headers=admin_headers).json()
    default = next(o for o in orgs if o["slug"] == "default")
    assert default["contained"] is False


def test_auto_resume_is_recorded_in_ledger(client, admin_headers):
    agent = _agent_with_allow(client, admin_headers)
    client.post("/api/orgs/containment", headers=admin_headers,
                json={"contained": True, "duration_minutes": 5})
    from datetime import datetime, timedelta, timezone
    from sqlalchemy import select
    from agentops.database import SessionLocal
    from agentops.models import Organization
    with SessionLocal() as db:
        org = db.scalar(select(Organization).where(Organization.slug == "default"))
        org.contained_until = datetime.now(timezone.utc) - timedelta(seconds=1)
        db.commit()
    _authorize(client, agent["api_key"])  # triggers lazy auto-resume
    records = client.get("/api/audit/records?action_type=org.resume",
                         headers=admin_headers).json()
    assert any("auto-lifted" in r["reason"] for r in records)


def test_containment_sweeper_lifts_expired(client, admin_headers, db):
    client.post("/api/orgs/containment", headers=admin_headers,
                json={"contained": True, "duration_minutes": 10})
    from datetime import datetime, timedelta, timezone
    from sqlalchemy import select
    from agentops.containment import sweep_expired
    from agentops.models import Organization
    org = db.scalar(select(Organization).where(Organization.slug == "default"))
    org.contained_until = datetime.now(timezone.utc) - timedelta(minutes=1)
    db.commit()
    assert sweep_expired(db) == 1
    db.refresh(org)
    assert org.contained is False


def test_indefinite_containment_has_no_until(client, admin_headers):
    r = client.post("/api/orgs/containment", headers=admin_headers,
                    json={"contained": True, "reason": "no window"})
    assert r.json()["contained_until"] is None  # holds until manual resume


def test_non_superadmin_cannot_contain_other_orgs(client, admin_headers):
    org = client.post("/api/orgs", json={"name": "Delta", "slug": "delta"},
                      headers=admin_headers).json()
    client.post(f"/api/orgs/{org['id']}/users",
                json={"email": "admin@delta.example", "password": "deltapass123", "role": "admin"},
                headers=admin_headers)
    d = client.post("/api/auth/login",
                    json={"email": "admin@delta.example", "password": "deltapass123"}).json()
    d_headers = {"Authorization": f"Bearer {d['access_token']}"}
    # A tenant admin hitting the superadmin cross-org endpoint is forbidden.
    r = client.post("/api/orgs/1/containment", headers=d_headers,
                    json={"contained": True})
    assert r.status_code == 403
