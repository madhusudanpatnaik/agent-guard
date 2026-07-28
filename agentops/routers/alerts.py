"""Risk alerts — the "respond" side of detect & respond (scoped to the caller's org)."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Alert, AlertStatus, User
from ..schemas import AlertOut
from ..security import require_admin
from ..tenancy import owned_or_404, scope

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("", response_model=list[AlertOut])
def list_alerts(
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
    status_filter: str | None = Query(default=None, alias="status"),
    severity: str | None = None,
    limit: int = Query(default=100, le=1000),
    offset: int = Query(default=0, ge=0),
) -> list[Alert]:
    stmt = scope(select(Alert), Alert, user).order_by(Alert.created_at.desc())
    if status_filter:
        stmt = stmt.where(Alert.status == status_filter)
    if severity:
        stmt = stmt.where(Alert.severity == severity)
    return list(db.scalars(stmt.offset(offset).limit(limit)))


@router.get("/count")
def open_count(db: Session = Depends(get_db), user: User = Depends(require_admin)) -> dict:
    n = db.scalar(
        scope(select(func.count(Alert.id)), Alert, user).where(Alert.status == AlertStatus.OPEN)
    ) or 0
    return {"open": n}


@router.post("/{alert_id}/ack", response_model=AlertOut)
def acknowledge(
    alert_id: int, db: Session = Depends(get_db), user: User = Depends(require_admin)
) -> Alert:
    alert = owned_or_404(db.get(Alert, alert_id), user, "Alert")
    alert.status = AlertStatus.ACKNOWLEDGED
    alert.acknowledged_by = user.email
    alert.acknowledged_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(alert)
    return alert
