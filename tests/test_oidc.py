"""Tests for enterprise SSO via OIDC.

A real RSA keypair signs the ID token and the module verifies the RS256 signature
against a served JWKS — so the crypto path is exercised for real, not mocked.
"""

import base64
import json
import time
from urllib.parse import parse_qs, urlparse

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from agentops import oidc
from agentops.config import get_settings


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _int_b64(i: int) -> str:
    return _b64url(i.to_bytes((i.bit_length() + 7) // 8, "big"))


@pytest.fixture
def oidc_setup(monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "oidc_issuer", "https://idp.example")
    monkeypatch.setattr(s, "oidc_client_id", "agentops-client")
    monkeypatch.setattr(s, "oidc_client_secret", "shh")
    monkeypatch.setattr(s, "oidc_redirect_uri", "http://testserver/api/auth/oidc/callback")

    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    nums = priv.public_key().public_numbers()
    jwks = {"keys": [{"kty": "RSA", "kid": "kid1", "use": "sig", "alg": "RS256",
                      "n": _int_b64(nums.n), "e": _int_b64(nums.e)}]}

    monkeypatch.setattr(oidc, "discover", lambda: {
        "authorization_endpoint": "https://idp.example/authorize",
        "token_endpoint": "https://idp.example/token",
        "jwks_uri": "https://idp.example/jwks",
    })
    monkeypatch.setattr(oidc, "_jwks", lambda: jwks)

    def make_token(claims: dict, key=priv, kid="kid1") -> str:
        header = {"alg": "RS256", "typ": "JWT", "kid": kid}
        seg = [_b64url(json.dumps(header).encode()), _b64url(json.dumps(claims).encode())]
        sig = key.sign(".".join(seg).encode(), padding.PKCS1v15(), hashes.SHA256())
        seg.append(_b64url(sig))
        return ".".join(seg)

    return {"make_token": make_token, "monkeypatch": monkeypatch, "priv": priv, "other": other}


def _claims(**over):
    base = {"iss": "https://idp.example", "aud": "agentops-client",
            "exp": int(time.time()) + 300, "email": "alice@corp.example"}
    base.update(over)
    return base


def _get_state(client) -> str:
    r = client.get("/api/auth/oidc/login", follow_redirects=False)
    assert r.status_code == 307
    return parse_qs(urlparse(r.headers["location"]).query)["state"][0]


def _callback_with(client, oidc_setup, claims, key=None):
    token = oidc_setup["make_token"](claims, key=key) if key else oidc_setup["make_token"](claims)
    oidc_setup["monkeypatch"].setattr(oidc, "exchange_code", lambda code: {"id_token": token})
    state = _get_state(client)
    return client.get(f"/api/auth/oidc/callback?code=abc&state={state}")


# --------------------------------------------------------------------------- #

def test_login_redirects_to_idp(client, oidc_setup):
    r = client.get("/api/auth/oidc/login", follow_redirects=False)
    assert r.status_code == 307
    loc = r.headers["location"]
    assert loc.startswith("https://idp.example/authorize")
    q = parse_qs(urlparse(loc).query)
    assert q["client_id"] == ["agentops-client"]
    assert q["response_type"] == ["code"]
    assert "state" in q


def test_full_sso_flow_provisions_user_and_issues_token(client, oidc_setup):
    r = _callback_with(client, oidc_setup, _claims())
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["user"]["email"] == "alice@corp.example"
    assert data["user"]["role"] == "viewer"          # least-privilege default
    # The AgentOps session token actually works.
    me = client.get("/api/auth/me",
                    headers={"Authorization": f"Bearer {data['access_token']}"})
    assert me.status_code == 200
    assert me.json()["email"] == "alice@corp.example"


def test_bad_signature_rejected(client, oidc_setup):
    # Signed by a key that is NOT in the served JWKS.
    r = _callback_with(client, oidc_setup, _claims(), key=oidc_setup["other"])
    assert r.status_code == 401
    assert "signature" in r.json()["detail"]


def test_audience_mismatch_rejected(client, oidc_setup):
    r = _callback_with(client, oidc_setup, _claims(aud="some-other-client"))
    assert r.status_code == 401


def test_expired_token_rejected(client, oidc_setup):
    r = _callback_with(client, oidc_setup, _claims(exp=int(time.time()) - 10))
    assert r.status_code == 401


def test_domain_restriction_enforced(client, oidc_setup):
    oidc_setup["monkeypatch"].setattr(get_settings(), "oidc_allowed_domain", "corp.example")
    r = _callback_with(client, oidc_setup, _claims(email="mallory@evil.com"))
    assert r.status_code == 403


def test_unverified_email_rejected(client, oidc_setup):
    r = _callback_with(client, oidc_setup, _claims(email_verified=False))
    assert r.status_code == 401
    assert "not verified" in r.json()["detail"]


def test_invalid_state_rejected(client, oidc_setup):
    token = oidc_setup["make_token"](_claims())
    oidc_setup["monkeypatch"].setattr(oidc, "exchange_code", lambda code: {"id_token": token})
    r = client.get("/api/auth/oidc/callback?code=abc&state=not-a-real-state")
    assert r.status_code == 400


def test_oidc_disabled_by_default(client):
    # No oidc_setup fixture -> OIDC not configured.
    assert client.get("/api/auth/oidc/login").status_code == 400
    assert client.get("/api/auth/oidc/callback?code=x&state=y").status_code == 400


def test_auto_provision_refuses_when_default_org_is_missing(client, oidc_setup, db):
    """A missing bootstrap org must refuse provisioning, not create an orphan.

    Falling back to org_id=None would be worse than refusing: SQLAlchemy
    compiles `column == None` to `IS NULL`, so a second orphaned user created
    later would match this one under tenancy.scope() and share visibility into
    its org-scoped resources -- a cross-tenant leak between two accounts that
    were never meant to be related at all.
    """
    from agentops.models import Organization

    db.query(Organization).filter(Organization.slug == "default").delete()
    db.commit()

    r = _callback_with(client, oidc_setup, _claims(email="new-user@corp.example"))
    assert r.status_code == 500
    assert "default organization" in r.json()["detail"].lower()

    from agentops.models import User

    assert db.query(User).filter(User.email == "new-user@corp.example").first() is None
