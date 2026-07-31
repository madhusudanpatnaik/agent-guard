"""Console operator authentication."""

from __future__ import annotations

import logging
import secrets
import time

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import oidc
from ..config import get_settings
from ..database import get_db
from ..models import Organization, User
from ..schemas import LoginRequest, TokenResponse, UserOut
from ..security import create_access_token, get_current_user, hash_password, verify_password

router = APIRouter(prefix="/auth", tags=["auth"])
_log = logging.getLogger("agentops.auth")

# Precomputed once so the "no such user" path performs the same PBKDF2 work as a
# real verification, closing the account-enumeration timing side channel.
_DUMMY_HASH = hash_password("agentops-constant-time-equalizer")

# --- In-memory login rate limiter -------------------------------------------
# Tracks failed login timestamps per source IP. No external dependency needed;
# entries are lazily cleaned on each check.

_login_failures: dict[str, list[float]] = {}


def _check_login_rate(client_ip: str) -> None:
    """Raise HTTP 429 if the source IP has exceeded the login failure limit."""
    settings = get_settings()
    max_attempts = settings.login_rate_limit_count
    window = settings.login_rate_limit_window
    now = time.monotonic()

    attempts = _login_failures.get(client_ip, [])
    # Prune attempts outside the window.
    attempts = [t for t in attempts if now - t < window]
    _login_failures[client_ip] = attempts

    if len(attempts) >= max_attempts:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            f"Too many login failures. Try again in {window} seconds.",
        )


def _record_login_failure(client_ip: str) -> None:
    """Record a failed login attempt from a source IP."""
    _login_failures.setdefault(client_ip, []).append(time.monotonic())


@router.post("/login", response_model=TokenResponse)
def login(body: LoginRequest, request: Request, db: Session = Depends(get_db)) -> TokenResponse:
    client_ip = request.client.host if request.client else "unknown"
    _check_login_rate(client_ip)

    user = db.scalar(select(User).where(User.email == body.email.lower().strip()))
    if not user:
        verify_password(body.password, _DUMMY_HASH)  # equalize timing
        _record_login_failure(client_ip)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials")
    if not verify_password(body.password, user.password_hash):
        _record_login_failure(client_ip)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials")
    if not user.is_active:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Account disabled")

    # Successful login clears the failure counter.
    _login_failures.pop(client_ip, None)

    token = create_access_token(str(user.id), extra={"role": user.role, "email": user.email})
    return TokenResponse(
        access_token=token,
        expires_in=get_settings().access_token_ttl_seconds,
        user=UserOut.model_validate(user),
    )


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)) -> UserOut:
    return UserOut.model_validate(user)


# --- Enterprise SSO (OpenID Connect) ----------------------------------------
# CSRF state store (in-memory; a multi-instance deployment would use Redis).
_oidc_states: dict[str, float] = {}
_OIDC_STATE_TTL = 600  # seconds


@router.get("/oidc/login")
def oidc_login() -> RedirectResponse:
    """Begin SSO: redirect the operator to the configured IdP."""
    if not get_settings().oidc_enabled:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "OIDC is not configured")
    state = secrets.token_urlsafe(24)
    _oidc_states[state] = time.monotonic()
    try:
        url = oidc.authorize_url(state)
    except (oidc.OIDCError, httpx.HTTPError) as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"IdP discovery failed: {exc}")
    return RedirectResponse(url, status_code=status.HTTP_307_TEMPORARY_REDIRECT)


@router.get("/oidc/callback", response_model=TokenResponse)
def oidc_callback(
    code: str, state: str, db: Session = Depends(get_db)
) -> TokenResponse:
    """Complete SSO: validate the IdP ID token and issue an AgentOps session."""
    settings = get_settings()
    if not settings.oidc_enabled:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "OIDC is not configured")

    # Validate + consume the CSRF state.
    issued = _oidc_states.pop(state, None)
    if issued is None or time.monotonic() - issued > _OIDC_STATE_TTL:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid or expired state")

    try:
        tokens = oidc.exchange_code(code)
        claims = oidc.verify_id_token(tokens["id_token"])
    except (oidc.OIDCError, KeyError, httpx.HTTPError) as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, f"OIDC login failed: {exc}")

    email = (claims.get("email") or "").lower().strip()
    if not email:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "IdP did not return an email claim")
    verified = claims.get("email_verified", True)
    if verified is False or str(verified).lower() == "false":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "IdP reports the email is not verified")
    if settings.oidc_allowed_domain and not email.endswith("@" + settings.oidc_allowed_domain):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            f"email domain not permitted (must be @{settings.oidc_allowed_domain})",
        )

    user = db.scalar(select(User).where(User.email == email))
    if not user:
        # Auto-provision into the default org with a least-privilege role; "!oidc"
        # is an unusable password hash so SSO accounts can never sign in by password.
        org = db.scalar(select(Organization).where(Organization.slug == "default"))
        if org is None:
            # Bootstrap invariant broken (no "default" org exists). Falling back
            # to org_id=None would be worse than refusing: SQLAlchemy compiles
            # `column == None` to `IS NULL`, so every future orphaned user would
            # match every other orphaned user under tenancy.scope() and share
            # visibility into each other's org-scoped resources. Fail closed.
            _log.error("OIDC auto-provision refused: no 'default' organization exists")
            raise HTTPException(
                status.HTTP_500_INTERNAL_SERVER_ERROR,
                "SSO sign-in is temporarily unavailable (no default organization "
                "configured) — contact an operator",
            )
        user = User(
            email=email, password_hash="!oidc", role=settings.oidc_default_role,
            org_id=org.id,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
    if not user.is_active:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Account disabled")

    token = create_access_token(str(user.id), extra={"role": user.role, "email": user.email})
    return TokenResponse(
        access_token=token,
        expires_in=settings.access_token_ttl_seconds,
        user=UserOut.model_validate(user),
    )
