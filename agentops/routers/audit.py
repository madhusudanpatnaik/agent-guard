"""Read + integrity-verify the tamper-evident audit ledger."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..audit.ledger import verify_chain
from ..database import get_db
from ..models import AuditRecord, User
from ..schemas import AuditRecordOut, ChainStatusOut
from ..security import get_current_user, require_superadmin
from ..tenancy import owned_or_404, scope

router = APIRouter(prefix="/audit", tags=["audit"])

_EXPORT_COLUMNS = [
    "seq", "created_at", "agent_name", "role_name", "action_type",
    "resource", "decision", "reason", "dlp_count", "hash",
]


@router.get("/records", response_model=list[AuditRecordOut])
def list_records(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    limit: int = Query(default=100, le=1000),
    offset: int = Query(default=0, ge=0),
    decision: str | None = None,
    agent_id: int | None = None,
    action_type: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
) -> list[AuditRecord]:
    stmt = scope(select(AuditRecord), AuditRecord, user).order_by(AuditRecord.seq.desc())
    if decision:
        stmt = stmt.where(AuditRecord.decision == decision)
    if agent_id is not None:
        stmt = stmt.where(AuditRecord.agent_id == agent_id)
    if action_type:
        stmt = stmt.where(AuditRecord.action_type == action_type)
    if since:
        stmt = stmt.where(AuditRecord.created_at >= since)
    if until:
        stmt = stmt.where(AuditRecord.created_at <= until)
    stmt = stmt.offset(offset).limit(limit)
    return list(db.scalars(stmt))


@router.get("/export")
def export(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    fmt: str = Query(default="csv", pattern="^(csv|jsonl)$"),
    decision: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int = Query(default=100_000, le=1_000_000),
) -> StreamingResponse:
    """Stream the audit trail for auditors, as CSV or JSON Lines.

    Filterable by decision and time range. Streams so exporting a large ledger
    never materializes the whole thing in memory.
    """
    stmt = scope(select(AuditRecord), AuditRecord, user).order_by(AuditRecord.seq.asc())
    if decision:
        stmt = stmt.where(AuditRecord.decision == decision)
    if since:
        stmt = stmt.where(AuditRecord.created_at >= since)
    if until:
        stmt = stmt.where(AuditRecord.created_at <= until)
    stmt = stmt.limit(limit)

    def _row(rec: AuditRecord) -> dict:
        return {
            "seq": rec.seq,
            "created_at": rec.created_at.isoformat() if rec.created_at else "",
            "agent_name": rec.agent_name,
            "role_name": rec.role_name,
            "action_type": rec.action_type,
            "resource": rec.resource,
            "decision": rec.decision,
            "reason": rec.reason,
            "dlp_count": rec.dlp_count,
            "hash": rec.hash,
        }

    if fmt == "jsonl":
        def _gen_jsonl():
            for rec in db.scalars(stmt):
                yield json.dumps(_row(rec)) + "\n"

        return StreamingResponse(
            _gen_jsonl(), media_type="application/x-ndjson",
            headers={"Content-Disposition": "attachment; filename=agentops-audit.jsonl"},
        )

    def _gen_csv():
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=_EXPORT_COLUMNS)
        writer.writeheader()
        yield buf.getvalue()
        for rec in db.scalars(stmt):
            buf.seek(0)
            buf.truncate(0)
            writer.writerow(_row(rec))
            yield buf.getvalue()

    return StreamingResponse(
        _gen_csv(), media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=agentops-audit.csv"},
    )


@router.get("/verify", response_model=ChainStatusOut)
def verify(db: Session = Depends(get_db), _: User = Depends(require_superadmin)) -> ChainStatusOut:
    # Global chain integrity is a platform concern (and exposes the global chain
    # length), so it is restricted to the superadmin. Tenants get a per-org
    # `ledger_valid` signal from /api/dashboard/stats.
    status = verify_chain(db)
    return ChainStatusOut(**status.as_dict())


@router.get("/head")
def head(db: Session = Depends(get_db), _: User = Depends(require_superadmin)) -> dict:
    """Current ledger head (seq + hash) — superadmin only (global chain metadata).

    Poll this from an external monitor and pin the value in a WORM store /
    transparency log to get third-party-provable protection against head
    truncation, on top of the built-in anchor file.
    """
    rec = db.scalar(select(AuditRecord).order_by(AuditRecord.seq.desc()).limit(1))
    if rec is None:
        return {"seq": None, "hash": None, "count": 0}
    return {"seq": rec.seq, "hash": rec.hash, "count": rec.seq + 1}


@router.get("/records/{seq}", response_model=AuditRecordOut)
def get_record(
    seq: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)
) -> AuditRecord:
    rec = db.scalar(select(AuditRecord).where(AuditRecord.seq == seq))
    return owned_or_404(rec, user, "Record")
