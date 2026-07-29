"""SCIM 2.0 provisioning — automated user lifecycle from the enterprise IdP.

Okta / Azure AD / OneLogin push user create / update / deactivate to these
endpoints so console operators are provisioned and de-provisioned automatically
instead of by hand. This implements the SCIM 2.0 ``/Users`` resource (RFC 7644)
sufficient for the major IdPs: create, get, list-with-filter, replace, patch
(the ``active`` toggle IdPs use to deactivate), and delete.

Authentication is a bearer token the IdP is configured with
(``AGENTOPS_SCIM_BEARER_TOKEN``); when unset, SCIM is disabled and every route
returns 404. The token resolves to exactly the "default" org — SCIM has always
been a single-tenant-per-token feature (there is one global token setting), and
every handler now enforces that binding explicitly rather than implicitly.

Every SCIM route is scoped to that one resolved org: list/get/replace/patch/delete
all filter or verify ``User.org_id == org.id``. This was NOT previously true —
every route operated on the User table by raw ID with no org filter at all, so
the one token configured for one tenant's IdP could list, read, and rewrite every
user in every org on the deployment. Per-org SCIM tokens (letting more than one
tenant provision independently) are not implemented; that is a real limitation,
tracked as a follow-up, not something to paper over.
"""

from __future__ import annotations

import hmac
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..database import get_db
from ..models import Organization, User

router = APIRouter(prefix="/scim/v2", tags=["scim"])

_USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
_LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
_ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"
_PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"

# SCIM role mapping is deliberately least-privilege; elevate in-app afterwards.
_DEFAULT_ROLE = "viewer"


def require_scim_auth(authorization: str | None = Header(default=None),
                      db: Session = Depends(get_db)) -> Organization:
    """Gate every SCIM route on the configured bearer token, and resolve the ONE
    org it is bound to. Every route depends on this for its org, not just its auth.
    """
    token = get_settings().scim_bearer_token
    if not token:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "SCIM is not enabled")
    presented = (authorization or "").strip()
    if not hmac.compare_digest(presented, f"Bearer {token}"):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid SCIM bearer token")
    org = _default_org(db)
    if org is None:
        # Bootstrap invariant broken (no "default" org exists) — fail closed
        # rather than provision/return users into an undefined tenant.
        raise HTTPException(status.HTTP_404_NOT_FOUND, "SCIM is not enabled")
    return org


def _scim_error(detail: str, code: int) -> HTTPException:
    return HTTPException(code, detail)


def _to_scim(user: User, request: Request | None = None) -> dict:
    created = (user.created_at or datetime.now(timezone.utc)).isoformat()
    location = None
    if request is not None:
        location = str(request.url_for("scim_get_user", user_id=user.id))
    return {
        "schemas": [_USER_SCHEMA],
        "id": str(user.id),
        "userName": user.email,
        "active": user.is_active,
        "emails": [{"value": user.email, "primary": True}],
        "meta": {"resourceType": "User", "created": created, "lastModified": created,
                 **({"location": location} if location else {})},
    }


def _default_org(db: Session) -> Organization | None:
    return db.scalar(select(Organization).where(Organization.slug == "default"))


def _extract_username(body: dict) -> str:
    username = (body.get("userName") or "").lower().strip()
    if not username:
        emails = body.get("emails") or []
        if emails:
            username = str(emails[0].get("value", "")).lower().strip()
    return username


def _scoped_user(db: Session, user_id: int, org: Organization) -> User:
    """Fetch a user by id, but ONLY if it belongs to the token's resolved org.

    A cross-org id returns 404 rather than 403 — SCIM callers get no signal that
    a user id exists at all outside their own tenant, matching the rest of the
    app's "never reveal existence across tenants" rule (see tenancy.py).
    """
    user = db.get(User, user_id)
    if not user or user.org_id != org.id:
        raise _scim_error("User not found", status.HTTP_404_NOT_FOUND)
    return user


@router.post("/Users", status_code=status.HTTP_201_CREATED)
def scim_create_user(body: dict, request: Request, response: Response,
                     db: Session = Depends(get_db),
                     org: Organization = Depends(require_scim_auth)) -> dict:
    username = _extract_username(body)
    if not username:
        raise _scim_error("userName is required", status.HTTP_400_BAD_REQUEST)

    existing = db.scalar(select(User).where(User.email == username))
    if existing:
        # SCIM: creating an existing user is a 409 conflict.
        raise _scim_error("User already exists", status.HTTP_409_CONFLICT)

    user = User(
        email=username,
        password_hash="!scim",  # unusable — SCIM users authenticate via SSO
        role=_DEFAULT_ROLE,
        is_active=bool(body.get("active", True)),
        org_id=org.id,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    response.headers["Location"] = str(request.url_for("scim_get_user", user_id=user.id))
    return _to_scim(user, request)


@router.get("/Users/{user_id}", name="scim_get_user")
def scim_get_user(user_id: int, request: Request, db: Session = Depends(get_db),
                  org: Organization = Depends(require_scim_auth)) -> dict:
    return _to_scim(_scoped_user(db, user_id, org), request)


@router.get("/Users")
def scim_list_users(request: Request, db: Session = Depends(get_db),
                    org: Organization = Depends(require_scim_auth),
                    filter: str | None = Query(default=None),
                    startIndex: int = Query(default=1, ge=1),
                    count: int = Query(default=100, ge=0, le=1000)) -> dict:
    stmt = select(User).where(User.org_id == org.id)
    # IdPs probe existence with:  filter=userName eq "alice@corp"
    if filter and "userName" in filter and " eq " in filter:
        wanted = filter.split(" eq ", 1)[1].strip().strip('"').lower()
        stmt = stmt.where(User.email == wanted)
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = list(db.scalars(stmt.offset(startIndex - 1).limit(count)))
    return {
        "schemas": [_LIST_SCHEMA],
        "totalResults": total,
        "startIndex": startIndex,
        "itemsPerPage": len(rows),
        "Resources": [_to_scim(u, request) for u in rows],
    }


@router.put("/Users/{user_id}")
def scim_replace_user(user_id: int, body: dict, request: Request,
                      db: Session = Depends(get_db),
                      org: Organization = Depends(require_scim_auth)) -> dict:
    user = _scoped_user(db, user_id, org)
    if "active" in body:
        user.is_active = bool(body["active"])
    new_name = _extract_username(body)
    if new_name:
        user.email = new_name
    db.commit()
    db.refresh(user)
    return _to_scim(user, request)


@router.patch("/Users/{user_id}")
def scim_patch_user(user_id: int, body: dict, request: Request,
                    db: Session = Depends(get_db),
                    org: Organization = Depends(require_scim_auth)) -> dict:
    """Handle the PatchOp IdPs use to (de)activate a user."""
    user = _scoped_user(db, user_id, org)
    for op in body.get("Operations", []):
        if str(op.get("op", "")).lower() not in {"replace", "add"}:
            continue
        value = op.get("value")
        path = (op.get("path") or "").lower()
        if path == "active" and value is not None:
            user.is_active = _as_bool(value)
        elif isinstance(value, dict) and "active" in value:
            user.is_active = _as_bool(value["active"])
    db.commit()
    db.refresh(user)
    return _to_scim(user, request)


@router.delete("/Users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def scim_delete_user(user_id: int, db: Session = Depends(get_db),
                     org: Organization = Depends(require_scim_auth)) -> None:
    user = _scoped_user(db, user_id, org)
    # Soft-deactivate rather than hard-delete so the audit trail keeps referring
    # to a real principal; IdPs treat 204 as success either way.
    user.is_active = False
    db.commit()


def _as_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"true", "1", "yes"}
