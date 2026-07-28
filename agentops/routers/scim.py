"""SCIM 2.0 provisioning — automated user lifecycle from the enterprise IdP.

Okta / Azure AD / OneLogin push user create / update / deactivate to these
endpoints so console operators are provisioned and de-provisioned automatically
instead of by hand. This implements the SCIM 2.0 ``/Users`` resource (RFC 7644)
sufficient for the major IdPs: create, get, list-with-filter, replace, patch
(the ``active`` toggle IdPs use to deactivate), and delete.

Authentication is a bearer token the IdP is configured with
(``AGENTOPS_SCIM_BEARER_TOKEN``); when unset, SCIM is disabled and every route
returns 404. Provisioned users land in the default org with a least-privilege
role and an unusable password (SSO-only), mirroring the OIDC auto-provision path.
"""

from __future__ import annotations

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


def require_scim_auth(authorization: str | None = Header(default=None)) -> None:
    """Gate every SCIM route on the configured bearer token."""
    token = get_settings().scim_bearer_token
    if not token:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "SCIM is not enabled")
    if not authorization or authorization.strip() != f"Bearer {token}":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid SCIM bearer token")


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


@router.post("/Users", status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_scim_auth)])
def scim_create_user(body: dict, request: Request, response: Response,
                     db: Session = Depends(get_db)) -> dict:
    username = _extract_username(body)
    if not username:
        raise _scim_error("userName is required", status.HTTP_400_BAD_REQUEST)

    existing = db.scalar(select(User).where(User.email == username))
    if existing:
        # SCIM: creating an existing user is a 409 conflict.
        raise _scim_error("User already exists", status.HTTP_409_CONFLICT)

    org = _default_org(db)
    user = User(
        email=username,
        password_hash="!scim",  # unusable — SCIM users authenticate via SSO
        role=_DEFAULT_ROLE,
        is_active=bool(body.get("active", True)),
        org_id=org.id if org else None,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    response.headers["Location"] = str(request.url_for("scim_get_user", user_id=user.id))
    return _to_scim(user, request)


@router.get("/Users/{user_id}", name="scim_get_user",
            dependencies=[Depends(require_scim_auth)])
def scim_get_user(user_id: int, request: Request, db: Session = Depends(get_db)) -> dict:
    user = db.get(User, user_id)
    if not user:
        raise _scim_error("User not found", status.HTTP_404_NOT_FOUND)
    return _to_scim(user, request)


@router.get("/Users", dependencies=[Depends(require_scim_auth)])
def scim_list_users(request: Request, db: Session = Depends(get_db),
                    filter: str | None = Query(default=None),
                    startIndex: int = Query(default=1, ge=1),
                    count: int = Query(default=100, ge=0, le=1000)) -> dict:
    stmt = select(User)
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


@router.put("/Users/{user_id}", dependencies=[Depends(require_scim_auth)])
def scim_replace_user(user_id: int, body: dict, request: Request,
                      db: Session = Depends(get_db)) -> dict:
    user = db.get(User, user_id)
    if not user:
        raise _scim_error("User not found", status.HTTP_404_NOT_FOUND)
    if "active" in body:
        user.is_active = bool(body["active"])
    new_name = _extract_username(body)
    if new_name:
        user.email = new_name
    db.commit()
    db.refresh(user)
    return _to_scim(user, request)


@router.patch("/Users/{user_id}", dependencies=[Depends(require_scim_auth)])
def scim_patch_user(user_id: int, body: dict, request: Request,
                    db: Session = Depends(get_db)) -> dict:
    """Handle the PatchOp IdPs use to (de)activate a user."""
    user = db.get(User, user_id)
    if not user:
        raise _scim_error("User not found", status.HTTP_404_NOT_FOUND)
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


@router.delete("/Users/{user_id}", status_code=status.HTTP_204_NO_CONTENT,
               dependencies=[Depends(require_scim_auth)])
def scim_delete_user(user_id: int, db: Session = Depends(get_db)) -> None:
    user = db.get(User, user_id)
    if not user:
        raise _scim_error("User not found", status.HTTP_404_NOT_FOUND)
    # Soft-deactivate rather than hard-delete so the audit trail keeps referring
    # to a real principal; IdPs treat 204 as success either way.
    user.is_active = False
    db.commit()


def _as_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"true", "1", "yes"}
