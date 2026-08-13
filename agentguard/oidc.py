"""Enterprise SSO via OpenID Connect (authorization-code flow).

Operators sign in with the company IdP (Okta, Entra ID, Google Workspace, Auth0,
Keycloak, …). AgentGuard redirects to the IdP, then validates the returned **ID
token** — RS256 signature against the IdP's published JWKS, plus issuer, audience
and expiry — and issues its own short-lived session token. Users are
auto-provisioned on first login with a least-privilege default role.

RS256 verification is implemented on ``cryptography`` (already a dependency) so
there is no additional JWT library to vet for an air-gapped enterprise deploy.
"""

from __future__ import annotations

import base64
import json
import time
from urllib.parse import urlencode

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .config import get_settings


class OIDCError(Exception):
    """Raised for any OIDC configuration or token-validation failure."""


def _b64url_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def _http_get_json(url: str) -> dict:
    resp = httpx.get(url, timeout=5.0)
    resp.raise_for_status()
    return resp.json()


_discovery_cache: dict[str, dict] = {}


def discover() -> dict:
    """Fetch (and cache) the IdP's OpenID discovery document."""
    settings = get_settings()
    if not settings.oidc_issuer:
        raise OIDCError("OIDC is not configured")
    issuer = settings.oidc_issuer.rstrip("/")
    if issuer not in _discovery_cache:
        _discovery_cache[issuer] = _http_get_json(f"{issuer}/.well-known/openid-configuration")
    return _discovery_cache[issuer]


def authorize_url(state: str) -> str:
    settings = get_settings()
    doc = discover()
    query = urlencode({
        "response_type": "code",
        "client_id": settings.oidc_client_id,
        "redirect_uri": settings.oidc_redirect_uri,
        "scope": "openid email profile",
        "state": state,
    })
    return f"{doc['authorization_endpoint']}?{query}"


def exchange_code(code: str) -> dict:
    """Exchange an authorization code for tokens at the IdP's token endpoint."""
    settings = get_settings()
    doc = discover()
    resp = httpx.post(
        doc["token_endpoint"],
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": settings.oidc_redirect_uri,
            "client_id": settings.oidc_client_id,
            "client_secret": settings.oidc_client_secret,
        },
        timeout=5.0,
    )
    resp.raise_for_status()
    return resp.json()


def _jwks() -> dict:
    return _http_get_json(discover()["jwks_uri"])


def _public_key_for_kid(kid: str | None):
    for key in _jwks().get("keys", []):
        if key.get("kty") == "RSA" and (kid is None or key.get("kid") == kid):
            n = int.from_bytes(_b64url_decode(key["n"]), "big")
            e = int.from_bytes(_b64url_decode(key["e"]), "big")
            return rsa.RSAPublicNumbers(e, n).public_key()
    raise OIDCError("no matching RSA key in the IdP JWKS")


def verify_id_token(id_token: str) -> dict:
    """Verify an ID token's RS256 signature and standard claims; return the claims."""
    settings = get_settings()
    try:
        header_b64, payload_b64, sig_b64 = id_token.split(".")
    except ValueError as exc:
        raise OIDCError("malformed id_token") from exc

    header = json.loads(_b64url_decode(header_b64))
    if header.get("alg") != "RS256":
        raise OIDCError(f"unsupported id_token alg {header.get('alg')!r} (expected RS256)")

    key = _public_key_for_kid(header.get("kid"))
    signing_input = f"{header_b64}.{payload_b64}".encode()
    try:
        key.verify(_b64url_decode(sig_b64), signing_input, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature as exc:
        raise OIDCError("id_token signature verification failed") from exc

    claims = json.loads(_b64url_decode(payload_b64))
    if claims.get("iss", "").rstrip("/") != settings.oidc_issuer.rstrip("/"):
        raise OIDCError("id_token issuer mismatch")
    aud = claims.get("aud")
    audiences = aud if isinstance(aud, list) else [aud]
    if settings.oidc_client_id not in audiences:
        raise OIDCError("id_token audience mismatch")
    if int(claims.get("exp", 0)) < int(time.time()):
        raise OIDCError("id_token has expired")
    return claims
