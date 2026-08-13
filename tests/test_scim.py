"""Tests for SCIM 2.0 user provisioning."""

import pytest

from agentguard.config import get_settings

_TOKEN = "scim-secret-token"


@pytest.fixture
def scim(monkeypatch):
    monkeypatch.setattr(get_settings(), "scim_bearer_token", _TOKEN)
    return {"Authorization": f"Bearer {_TOKEN}"}


def test_scim_disabled_without_token(client):
    # No token configured -> SCIM returns 404.
    r = client.post("/api/scim/v2/Users", json={"userName": "x@corp"})
    assert r.status_code == 404


def test_scim_refuses_when_default_org_is_missing(client, scim, db):
    """A valid token must not provision (or serve) anything without a resolvable
    org -- see test_oidc.py's matching test for why org_id=None is unsafe, not
    merely inconvenient."""
    from agentguard.models import Organization

    db.query(Organization).filter(Organization.slug == "default").delete()
    db.commit()

    r = client.post("/api/scim/v2/Users", json={"userName": "x@corp"}, headers=scim)
    assert r.status_code == 404


def test_scim_requires_valid_bearer(client, scim):
    r = client.post("/api/scim/v2/Users", json={"userName": "x@corp"},
                    headers={"Authorization": "Bearer wrong"})
    assert r.status_code == 401


def test_scim_create_user(client, scim):
    r = client.post("/api/scim/v2/Users",
                    json={"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                          "userName": "alice@corp.example", "active": True},
                    headers=scim)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["userName"] == "alice@corp.example"
    assert body["active"] is True
    assert body["id"]
    assert "Location" in r.headers

    # The user actually exists in AgentGuard with a least-privilege role.
    from agentguard.database import SessionLocal
    from agentguard.models import User
    from sqlalchemy import select
    with SessionLocal() as db:
        u = db.scalar(select(User).where(User.email == "alice@corp.example"))
        assert u is not None and u.role == "viewer"
        assert u.password_hash == "!scim"  # SSO-only


def test_scim_duplicate_is_conflict(client, scim):
    client.post("/api/scim/v2/Users", json={"userName": "dup@corp"}, headers=scim)
    r = client.post("/api/scim/v2/Users", json={"userName": "dup@corp"}, headers=scim)
    assert r.status_code == 409


def test_scim_get_and_filter(client, scim):
    created = client.post("/api/scim/v2/Users", json={"userName": "bob@corp"},
                          headers=scim).json()
    uid = created["id"]
    got = client.get(f"/api/scim/v2/Users/{uid}", headers=scim)
    assert got.status_code == 200
    assert got.json()["userName"] == "bob@corp"

    listed = client.get('/api/scim/v2/Users?filter=userName eq "bob@corp"', headers=scim).json()
    assert listed["totalResults"] == 1
    assert listed["Resources"][0]["userName"] == "bob@corp"


def test_scim_patch_deactivates_user(client, scim):
    created = client.post("/api/scim/v2/Users", json={"userName": "carol@corp"},
                          headers=scim).json()
    uid = created["id"]
    r = client.patch(f"/api/scim/v2/Users/{uid}", headers=scim, json={
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "replace", "path": "active", "value": False}]})
    assert r.status_code == 200
    assert r.json()["active"] is False


def test_scim_patch_azure_style_value_object(client, scim):
    created = client.post("/api/scim/v2/Users", json={"userName": "dave@corp"},
                          headers=scim).json()
    uid = created["id"]
    # Azure AD sends {"op":"Replace","value":{"active":false}} with no path.
    r = client.patch(f"/api/scim/v2/Users/{uid}", headers=scim, json={
        "Operations": [{"op": "Replace", "value": {"active": False}}]})
    assert r.status_code == 200
    assert r.json()["active"] is False


def test_scim_delete_soft_deactivates(client, scim):
    created = client.post("/api/scim/v2/Users", json={"userName": "erin@corp"},
                          headers=scim).json()
    uid = created["id"]
    r = client.delete(f"/api/scim/v2/Users/{uid}", headers=scim)
    assert r.status_code == 204
    got = client.get(f"/api/scim/v2/Users/{uid}", headers=scim).json()
    assert got["active"] is False  # soft-deactivated, audit principal preserved


def test_scim_provisioned_user_cannot_password_login(client, scim):
    client.post("/api/scim/v2/Users", json={"userName": "frank@corp"}, headers=scim)
    r = client.post("/api/auth/login", json={"email": "frank@corp", "password": "anything"})
    assert r.status_code == 401  # unusable "!scim" hash
