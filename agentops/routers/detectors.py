"""Custom DLP detector registry — extend secret/PII detection without a fork.

Operators register org-scoped regex detectors that are merged with the built-in
detector set on the request-scan path. A house token format, an internal
employee-id pattern, a partner API-key prefix — all become first-class DLP
findings (redacted, severity-weighted, egress-blocking) with no code change.

Patterns are validated at write time (they must compile and stay within a length
bound) so a malformed rule is rejected up front rather than breaking scanning.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import get_db
from ..dlp.safe_regex import bounded_search, validate_pattern
from ..models import Detector, User
from ..schemas import DetectorIn, DetectorOut, DetectorTestRequest, DetectorTestResult
from ..security import require_admin
from ..tenancy import owned_or_404, scope

router = APIRouter(prefix="/detectors", tags=["detectors"])


def _validate_pattern(pattern: str) -> None:
    # Rejects invalid, over-long, AND catastrophic-backtracking (ReDoS) patterns
    # so a dangerous rule can never be persisted and reach the enforcement path.
    ok, error = validate_pattern(pattern)
    if not ok:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, error or "invalid pattern")


@router.get("", response_model=list[DetectorOut])
def list_detectors(
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
    limit: int = Query(default=100, le=1000),
    offset: int = Query(default=0, ge=0),
) -> list[Detector]:
    stmt = scope(select(Detector), Detector, user).order_by(Detector.name)
    return list(db.scalars(stmt.offset(offset).limit(limit)))


@router.post("", response_model=DetectorOut, status_code=status.HTTP_201_CREATED)
def create_detector(
    body: DetectorIn, db: Session = Depends(get_db), user: User = Depends(require_admin)
) -> Detector:
    _validate_pattern(body.pattern)
    if db.scalar(scope(select(Detector), Detector, user).where(Detector.name == body.name)):
        raise HTTPException(status.HTTP_409_CONFLICT, "Detector name already exists")
    det = Detector(
        org_id=user.org_id, name=body.name, description=body.description,
        pattern=body.pattern, severity=body.severity, enabled=body.enabled,
    )
    db.add(det)
    db.commit()
    db.refresh(det)
    return det


@router.post("/test", response_model=DetectorTestResult)
def test_detector(body: DetectorTestRequest, _: User = Depends(require_admin)) -> DetectorTestResult:
    """Validate a pattern and check whether it matches a sample (authoring aid).

    Both pattern and sample are caller-controlled, so the match runs under a hard
    wall-clock deadline in a killable subprocess — a catastrophic pattern can't
    hang the worker thread.
    """
    valid, matched, error = bounded_search(body.pattern, body.sample)
    return DetectorTestResult(valid=valid, matched=matched, error=error)


@router.put("/{detector_id}", response_model=DetectorOut)
def update_detector(
    detector_id: int, body: DetectorIn, db: Session = Depends(get_db),
    user: User = Depends(require_admin),
) -> Detector:
    det = owned_or_404(db.get(Detector, detector_id), user, "Detector")
    _validate_pattern(body.pattern)
    clash = db.scalar(scope(select(Detector), Detector, user).where(
        Detector.name == body.name, Detector.id != detector_id))
    if clash:
        raise HTTPException(status.HTTP_409_CONFLICT, "Detector name already exists")
    det.name = body.name
    det.description = body.description
    det.pattern = body.pattern
    det.severity = body.severity
    det.enabled = body.enabled
    db.commit()
    db.refresh(det)
    return det


@router.delete("/{detector_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_detector(
    detector_id: int, db: Session = Depends(get_db), user: User = Depends(require_admin)
) -> None:
    det = owned_or_404(db.get(Detector, detector_id), user, "Detector")
    db.delete(det)
    db.commit()
