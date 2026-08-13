"""Connector registry — upstream systems the plane calls on an agent's behalf.

Operators register a connector once with its credential; the plane stores the
secret encrypted and injects it at call time. Agents reference connectors by name
and never receive the secret.
"""

from __future__ import annotations

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import get_db
from ..egress import check_egress
from ..models import Connector, User
from ..schemas import ConnectorIn, ConnectorOut, ConnectorTestResult
from ..security import require_admin
from ..tenancy import owned_or_404, scope
from ..vault import encrypt_secret

router = APIRouter(prefix="/connectors", tags=["connectors"])


def _to_out(c: Connector) -> ConnectorOut:
    out = ConnectorOut.model_validate(c)
    out.has_secret = bool(c.auth_secret_encrypted)
    return out


def _connector_in_org(db: Session, connector_id: int, user: User) -> Connector:
    return owned_or_404(db.get(Connector, connector_id), user, "Connector")


@router.get("", response_model=list[ConnectorOut])
def list_connectors(
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
    limit: int = Query(default=100, le=1000),
    offset: int = Query(default=0, ge=0),
):
    stmt = scope(select(Connector), Connector, user).order_by(
        Connector.name).offset(offset).limit(limit)
    return [_to_out(c) for c in db.scalars(stmt)]


@router.post("", response_model=ConnectorOut, status_code=status.HTTP_201_CREATED)
def create_connector(
    body: ConnectorIn, db: Session = Depends(get_db), user: User = Depends(require_admin)
):
    if db.scalar(scope(select(Connector), Connector, user).where(Connector.name == body.name)):
        raise HTTPException(status.HTTP_409_CONFLICT, "Connector name already exists")
    c = Connector(
        org_id=user.org_id,
        name=body.name,
        description=body.description,
        kind=body.kind,
        base_url=body.base_url,
        auth_type=body.auth_type,
        auth_header_name=body.auth_header_name,
        auth_secret_encrypted=encrypt_secret(body.auth_secret) if body.auth_secret else "",
        max_response_bytes=body.max_response_bytes,
        writable=body.writable,
        max_write_rows=body.max_write_rows,
        enabled=body.enabled,
    )
    db.add(c)
    db.commit()
    db.refresh(c)
    return _to_out(c)


@router.put("/{connector_id}", response_model=ConnectorOut)
def update_connector(
    connector_id: int,
    body: ConnectorIn,
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
):
    c = _connector_in_org(db, connector_id, user)
    c.name = body.name
    c.description = body.description
    c.kind = body.kind
    c.base_url = body.base_url
    c.auth_type = body.auth_type
    c.auth_header_name = body.auth_header_name
    c.max_response_bytes = body.max_response_bytes
    c.writable = body.writable
    c.max_write_rows = body.max_write_rows
    c.enabled = body.enabled
    # Only replace the secret when a new one is supplied (empty = keep existing).
    if body.auth_secret:
        c.auth_secret_encrypted = encrypt_secret(body.auth_secret)
    db.commit()
    db.refresh(c)
    return _to_out(c)


@router.delete("/{connector_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_connector(
    connector_id: int, db: Session = Depends(get_db), user: User = Depends(require_admin)
):
    c = _connector_in_org(db, connector_id, user)
    db.delete(c)
    db.commit()


@router.post("/{connector_id}/test", response_model=ConnectorTestResult)
def test_connector(
    connector_id: int, db: Session = Depends(get_db), user: User = Depends(require_admin)
) -> ConnectorTestResult:
    """Verify upstream connectivity by sending a HEAD request to the connector's base URL."""
    c = _connector_in_org(db, connector_id, user)
    try:
        check_egress(c.base_url)  # SSRF guard (no-op unless enabled)
        with httpx.Client(timeout=5.0, follow_redirects=False) as client:
            resp = client.head(c.base_url)
        return ConnectorTestResult(
            name=c.name,
            reachable=True,
            status_code=resp.status_code,
        )
    except Exception as exc:
        return ConnectorTestResult(
            name=c.name,
            reachable=False,
            error=str(exc),
        )
