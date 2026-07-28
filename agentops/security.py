"""Authentication & cryptographic primitives.

Everything here is implemented on the Python standard library so the control
plane has no native build dependencies (important for reproducible, air-gapped
enterprise deploys):

* Console operators authenticate with a password (PBKDF2-HMAC-SHA256) and carry
  a compact HS256 JWT.
* Agents authenticate with an opaque API key; only its SHA-256 hash is stored.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from datetime import datetime, timezone
from typing import Any

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import get_settings
from .database import get_db
from .models import Agent, AgentStatus, User

# --------------------------------------------------------------------------- #
# Password hashing (PBKDF2-HMAC-SHA256)
# --------------------------------------------------------------------------- #

_PBKDF2_ROUNDS = 240_000


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _PBKDF2_ROUNDS)
    return f"pbkdf2_sha256${_PBKDF2_ROUNDS}${salt.hex()}${dk.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algo, rounds, salt_hex, hash_hex = encoded.split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(salt_hex), int(rounds)
        )
        return hmac.compare_digest(dk.hex(), hash_hex)
    except (ValueError, AttributeError):
        return False


# --------------------------------------------------------------------------- #
# API keys
# --------------------------------------------------------------------------- #

API_KEY_PREFIX = "agentops_sk_"


def generate_api_key() -> tuple[str, str, str]:
    """Return ``(plaintext, sha256_hash, display_prefix)``.

    The plaintext is returned to the caller exactly once; only the hash is
    persisted, so a database leak never exposes usable agent credentials.
    """
    secret = secrets.token_urlsafe(32)
    plaintext = f"{API_KEY_PREFIX}{secret}"
    return plaintext, hash_api_key(plaintext), plaintext[: len(API_KEY_PREFIX) + 6]


def hash_api_key(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode()).hexdigest()


# --------------------------------------------------------------------------- #
# JWT (compact HS256, no third-party dependency)
# --------------------------------------------------------------------------- #

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def create_access_token(subject: str, extra: dict[str, Any] | None = None) -> str:
    settings = get_settings()
    now = int(datetime.now(timezone.utc).timestamp())
    header = {"alg": settings.jwt_algorithm, "typ": "JWT"}
    payload: dict[str, Any] = {
        "sub": subject,
        "iat": now,
        "exp": now + settings.access_token_ttl_seconds,
    }
    if extra:
        payload.update(extra)

    segments = [
        _b64url_encode(json.dumps(header, separators=(",", ":")).encode()),
        _b64url_encode(json.dumps(payload, separators=(",", ":")).encode()),
    ]
    signing_input = ".".join(segments).encode()
    signature = hmac.new(settings.secret_key.encode(), signing_input, hashlib.sha256).digest()
    segments.append(_b64url_encode(signature))
    return ".".join(segments)


def decode_access_token(token: str) -> dict[str, Any]:
    settings = get_settings()
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
    except ValueError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Malformed token") from exc

    signing_input = f"{header_b64}.{payload_b64}".encode()
    expected = hmac.new(settings.secret_key.encode(), signing_input, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, _b64url_decode(sig_b64)):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token signature")

    payload = json.loads(_b64url_decode(payload_b64))
    if int(payload.get("exp", 0)) < int(datetime.now(timezone.utc).timestamp()):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token expired")
    return payload


# --------------------------------------------------------------------------- #
# FastAPI dependencies
# --------------------------------------------------------------------------- #

def get_current_user(
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> User:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing bearer token")
    token = authorization.split(" ", 1)[1].strip()
    payload = decode_access_token(token)
    user = db.get(User, int(payload.get("sub", 0)))
    if not user or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Unknown or inactive user")
    return user


def require_admin(user: User = Depends(get_current_user)) -> User:
    if user.role not in {"admin", "operator"}:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Requires operator privileges")
    return user


def require_superadmin(user: User = Depends(get_current_user)) -> User:
    """Platform operator: may create organizations and provision their users."""
    if not user.is_superadmin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Requires platform superadmin")
    return user


def require_viewer(user: User = Depends(get_current_user)) -> User:
    """Any authenticated user (admin, operator, or viewer) may access read-only endpoints."""
    if user.role not in {"admin", "operator", "viewer"}:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Requires at least viewer privileges")
    return user


def get_authenticated_agent(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> Agent:
    """Resolve the calling agent from an ``X-API-Key`` header (or bearer key)."""
    key = x_api_key
    if not key and authorization and authorization.lower().startswith("bearer "):
        candidate = authorization.split(" ", 1)[1].strip()
        if candidate.startswith(API_KEY_PREFIX):
            key = candidate
    if not key:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing agent API key")

    agent = db.scalar(select(Agent).where(Agent.api_key_hash == hash_api_key(key)))
    if not agent:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid API key")
    if agent.status != AgentStatus.ACTIVE:
        raise HTTPException(status.HTTP_403_FORBIDDEN, f"Agent is {agent.status}")

    agent.last_seen_at = datetime.now(timezone.utc)
    db.commit()
    return agent
