"""Compliance evidence reporting — auditor-ready proof from the audit ledger.

Turns the tamper-evident ledger into the artifact a CISO/compliance team
actually needs: control families mapped to concrete evidence, a cryptographic
attestation that the evidence itself is un-tampered, and an honest list of
controls that produced no evidence in the period.

Reports are read-only and org-scoped; generating one never mutates governance
state. Markdown rendering is offered so a report can be attached to an audit
without post-processing.
"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from ..compliance import FRAMEWORKS, build_report, default_window, render_markdown
from ..database import get_db
from ..models import Organization, User
from ..schemas import (
    ComplianceReportOut,
    ComplianceReportRequest,
    FrameworkControlOut,
    FrameworkOut,
)
from ..security import require_admin

router = APIRouter(prefix="/compliance", tags=["compliance"])


def _caller_org(db: Session, user: User) -> Organization:
    org = db.get(Organization, user.org_id) if user.org_id is not None else None
    if org is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND,
                            "No organization is associated with this account")
    return org


def _window(body_since: datetime | None, body_until: datetime | None
            ) -> tuple[datetime, datetime]:
    since, until = default_window()
    if body_since is not None:
        since = body_since
    if body_until is not None:
        until = body_until
    # Normalize to aware UTC so comparisons against ledger timestamps are sound.
    if since.tzinfo is None:
        since = since.replace(tzinfo=timezone.utc)
    if until.tzinfo is None:
        until = until.replace(tzinfo=timezone.utc)
    if since >= until:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            "'since' must be earlier than 'until'")
    return since, until


@router.get("/frameworks", response_model=list[FrameworkOut])
def list_frameworks(_: User = Depends(require_admin)) -> list[FrameworkOut]:
    """The control frameworks a report can be generated against."""
    return [
        FrameworkOut(
            id=key,
            name=fw["name"],
            controls=[
                FrameworkControlOut(id=c.id, title=c.title,
                                    requirement=c.requirement, how=c.how)
                for c in fw["controls"]
            ],
        )
        for key, fw in FRAMEWORKS.items()
    ]


@router.post("/report", response_model=ComplianceReportOut)
def generate_report(
    body: ComplianceReportRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
) -> ComplianceReportOut:
    """Generate an evidence report for the caller's org over a time window."""
    org = _caller_org(db, user)
    since, until = _window(body.since, body.until)
    try:
        report = build_report(db, org, body.framework.lower(), since, until)
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))
    return ComplianceReportOut(**report)


@router.post("/report.md", response_class=PlainTextResponse)
def generate_report_markdown(
    body: ComplianceReportRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
) -> PlainTextResponse:
    """The same report rendered as Markdown, ready to attach to an audit."""
    org = _caller_org(db, user)
    since, until = _window(body.since, body.until)
    try:
        report = build_report(db, org, body.framework.lower(), since, until)
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))
    return PlainTextResponse(
        render_markdown(report),
        media_type="text/markdown",
        headers={"Content-Disposition":
                 f'attachment; filename="agentops-{body.framework.lower()}-report.md"'},
    )


@router.get("/summary")
def compliance_summary(
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
    framework: str = Query(default="soc2"),
) -> dict:
    """Coverage headline for a framework (for the console dashboard card)."""
    org = _caller_org(db, user)
    since, until = default_window()
    try:
        report = build_report(db, org, framework.lower(), since, until)
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))
    return {
        "framework": report["framework"],
        "framework_name": report["framework_name"],
        "coverage": report["coverage"],
        "chain_valid": report["ledger_attestation"]["chain_valid"],
        "gaps": report["gaps"],
    }
