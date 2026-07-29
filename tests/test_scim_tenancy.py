"""SCIM must be scoped to the one org its token is bound to.

Reproduced against the running app before this fix: a bearer token configured
for one tenant's IdP could list every user across every org
(GET /api/scim/v2/Users), read any user by guessing a sequential id, and
rewrite/deactivate any account — including hijacking another org's admin login
email. SCIM had no org filter anywhere; every other multi-tenant router in this
codebase uses tenancy.scope()/owned_or_404(), SCIM alone did not.

There is no per-org SCIM token yet (a real, documented limitation) — the token
resolves to exactly the bootstrap "default" org. These tests prove that binding
is now enforced rather than absent: SCIM can provision and manage users in its
own org, and org_b's users are completely invisible and unreachable through it.
"""

from __future__ import annotations

import pytest

from agentops.config import get_settings
from agentops.database import SessionLocal
from agentops.models import User
from tests.test_tenancy import org_a, org_b  # noqa: F401 - reused fixtures

_TOKEN = "scim-secret-token"


@pytest.fixture
def scim(monkeypatch):
    monkeypatch.setattr(get_settings(), "scim_bearer_token", _TOKEN)
    return {"Authorization": f"Bearer {_TOKEN}"}


@pytest.fixture
def other_org_user(client, org_a, org_b):  # noqa: F811 - pytest fixture injection, not reassignment
    """A user that belongs to org_b, the SCIM token's own org has no claim to."""
    with SessionLocal() as db:
        user = db.query(User).filter(User.email == "admin@beta.example").one()
        return user.id


def test_scim_list_excludes_other_orgs_users(client, scim, other_org_user):
    r = client.get("/api/scim/v2/Users", headers=scim)
    assert r.status_code == 200
    emails = [u["userName"] for u in r.json()["Resources"]]
    assert "admin@beta.example" not in emails


def test_scim_get_other_orgs_user_is_404(client, scim, other_org_user):
    r = client.get(f"/api/scim/v2/Users/{other_org_user}", headers=scim)
    assert r.status_code == 404


def test_scim_cannot_rewrite_other_orgs_user(client, scim, other_org_user):
    r = client.put(f"/api/scim/v2/Users/{other_org_user}", headers=scim,
                   json={"userName": "pwned@attacker.example", "active": False})
    assert r.status_code == 404

    with SessionLocal() as db:
        after = db.get(User, other_org_user)
        assert after.email == "admin@beta.example"
        assert after.is_active is True


def test_scim_cannot_patch_other_orgs_user(client, scim, other_org_user):
    r = client.patch(f"/api/scim/v2/Users/{other_org_user}", headers=scim,
                     json={"Operations": [{"op": "replace", "path": "active", "value": False}]})
    assert r.status_code == 404
    with SessionLocal() as db:
        assert db.get(User, other_org_user).is_active is True


def test_scim_cannot_delete_other_orgs_user(client, scim, other_org_user):
    r = client.delete(f"/api/scim/v2/Users/{other_org_user}", headers=scim)
    assert r.status_code == 404
    with SessionLocal() as db:
        assert db.get(User, other_org_user).is_active is True


def test_scim_filter_cannot_find_other_orgs_user(client, scim, other_org_user):
    """The userName filter must also respect the org boundary."""
    r = client.get('/api/scim/v2/Users?filter=userName eq "admin@beta.example"', headers=scim)
    assert r.status_code == 200
    assert r.json()["totalResults"] == 0


def test_scim_created_user_lands_in_the_tokens_own_org(client, scim):
    r = client.post("/api/scim/v2/Users", headers=scim, json={"userName": "new@corp.example"})
    assert r.status_code == 201
    with SessionLocal() as db:
        created = db.query(User).filter(User.email == "new@corp.example").one()
        default_org_id = db.query(User).filter(
            User.email == "admin@agentops.local").one().org_id
        assert created.org_id == default_org_id


def test_scim_token_comparison_is_constant_time(monkeypatch):
    """Regression for the plain `!=` comparison that skipped hmac.compare_digest."""
    import inspect

    from agentops.routers import scim as scim_mod

    source = inspect.getsource(scim_mod.require_scim_auth)
    assert "hmac.compare_digest" in source
