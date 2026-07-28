"""Governed database access — read-only SQL through the control plane.

This extends the "the plane holds the credential, the agent never does" model
from HTTP to SQL databases. An operator registers a ``database`` connector whose
vaulted secret is a full SQLAlchemy DSN (e.g. ``postgresql+psycopg://ro_user:...``).
An agent submits a query; the plane:

  1. classifies the statement and **rejects anything that is not read-only**
     (only ``SELECT`` / ``WITH``) and rejects multi-statement input;
  2. authorizes it against RBAC policy (resource ``db:<connector>``, action
     ``db.select``) — including quota, rate, and approval constraints;
  3. runs it with **bound parameters** (injection-safe) against the vaulted DSN,
     capped to a maximum number of rows;
  4. **DLP-scans and redacts** the result rows before the agent sees them;
  5. logs the query and its result to the tamper-evident ledger.

Least privilege is defense-in-depth: the connector DSN should point at a
read-only database account, so the DB's own grants bound what any query can read.

Write support (INSERT/UPDATE/DELETE/DDL) is intentionally gated off in this
version — governed writes need transaction + rollback semantics that warrant
their own design — so the surface here stays provably read-only.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy import create_engine, select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from .audit.ledger import AuditLedger
from .dlp.scanner import scan_payload
from .gateway_service import _claim_approval, _restore_approval, authorize_action
from .models import Agent, Approval, AuditRecord, Connector, Decision
from .policy.engine import ActionRequest, PolicyDecision
from .utils import build_preview, payload_fingerprint
from .vault import decrypt_secret

# Only these leading keywords are ever executed. Everything else is refused
# before it reaches the database.
_READ_VERBS = {"SELECT", "WITH"}
# Writes are limited to DML; DDL (DROP/ALTER/TRUNCATE/CREATE/GRANT/...) is never run.
_WRITE_VERBS = {"INSERT", "UPDATE", "DELETE"}
_MAX_ROWS = 1000


@dataclass
class QueryResult:
    executed: bool
    decision: PolicyDecision
    audit_record: AuditRecord
    approval: Approval | None = None
    columns: list[str] = field(default_factory=list)
    rows: list[dict] = field(default_factory=list)
    row_count: int = 0
    response_dlp_findings: list[dict] = field(default_factory=list)
    error: str | None = None


def _classify(sql: str) -> tuple[str, str | None]:
    """Return ``(verb, error)``. ``error`` is non-None if the SQL is not allowed."""
    stripped = sql.strip().rstrip(";").strip()
    if not stripped:
        return "", "empty query"
    # Reject multiple statements (an internal ';' followed by more SQL).
    if len([s for s in stripped.split(";") if s.strip()]) > 1:
        return "", "multiple statements are not allowed; submit one query at a time"
    verb = stripped.split(None, 1)[0].upper()
    if verb not in _READ_VERBS:
        return verb, (
            f"'{verb}' is not permitted — this connector is read-only "
            f"(allowed: {', '.join(sorted(_READ_VERBS))})"
        )
    return verb, None


def _classify_write(sql: str) -> tuple[str, str | None]:
    """Return ``(verb, error)`` for a write. ``error`` is set if not permitted."""
    stripped = sql.strip().rstrip(";").strip()
    if not stripped:
        return "", "empty statement"
    if len([s for s in stripped.split(";") if s.strip()]) > 1:
        return "", "multiple statements are not allowed; submit one statement at a time"
    verb = stripped.split(None, 1)[0].upper()
    if verb not in _WRITE_VERBS:
        return verb, (
            f"'{verb}' is not a permitted write — only "
            f"{', '.join(sorted(_WRITE_VERBS))} are allowed (DDL and reads are refused)"
        )
    return verb, None


def _run_query(dsn: str, sql: str, params: dict) -> tuple[list[str], list[dict]]:
    engine = create_engine(dsn, pool_pre_ping=True)
    try:
        with engine.connect() as conn:
            # Defense in depth beyond the keyword allowlist: force a read-only
            # transaction so a statement that leads with SELECT/WITH but hides a
            # write (Postgres `SELECT ... INTO`, data-modifying CTEs) is rejected
            # by the database itself. Reads are always rolled back, never committed.
            trans = conn.begin()
            try:
                dialect = engine.dialect.name
                if dialect == "postgresql":
                    conn.execute(text("SET TRANSACTION READ ONLY"))
                elif dialect == "sqlite":
                    conn.execute(text("PRAGMA query_only = ON"))
                elif dialect == "mysql":
                    conn.execute(text("SET TRANSACTION READ ONLY"))
                result = conn.execute(text(sql), params or {})
                columns = list(result.keys())
                rows = [dict(zip(columns, row)) for row in result.fetchmany(_MAX_ROWS)]
            finally:
                trans.rollback()
        return columns, rows
    finally:
        engine.dispose()


def _run_write(dsn: str, sql: str, params: dict, max_rows: int) -> tuple[int, bool]:
    """Execute a write in a transaction. Returns ``(rows_affected, capped)``.

    If the statement would affect more than ``max_rows``, the transaction is
    **rolled back** and ``capped`` is True — nothing is persisted.
    """
    engine = create_engine(dsn, pool_pre_ping=True)
    try:
        with engine.connect() as conn:
            trans = conn.begin()
            result = conn.execute(text(sql), params or {})
            affected = result.rowcount
            if affected is not None and affected >= 0 and affected > max_rows:
                trans.rollback()
                return affected, True
            trans.commit()
            return (affected if affected is not None and affected >= 0 else 0), False
    finally:
        engine.dispose()


def execute_query(
    db: Session,
    agent: Agent,
    *,
    connector_name: str,
    sql: str,
    params: dict | None = None,
    metadata: dict | None = None,
    approval_id: int | None = None,
) -> QueryResult:
    connector = db.scalar(
        select(Connector).where(
            Connector.name == connector_name, Connector.org_id == agent.org_id
        )
    )
    if not connector or not connector.enabled:
        raise ValueError(f"unknown or disabled connector '{connector_name}'")
    if connector.kind != "database":
        raise ValueError(f"connector '{connector_name}' is not a database connector")

    verb, err = _classify(sql)
    resource = f"db:{connector_name}"
    action_type = f"db.{verb.lower()}" if verb else "db.query"
    ledger = AuditLedger(db)

    if err is not None:
        # Refused before authorization, but still recorded for the audit trail.
        rec = ledger.append(
            agent_id=agent.id, agent_name=agent.name,
            role_name=agent.role.name if agent.role else "",
            action_type=action_type, resource=resource,
            decision=Decision.DENY, reason=f"Query rejected: {err}",
            payload_preview=build_preview(sql), org_id=agent.org_id,
        )
        return QueryResult(
            executed=False,
            decision=PolicyDecision(Decision.DENY, err),
            audit_record=rec,
            error=err,
        )

    req = ActionRequest(
        action_type=action_type,
        resource=resource,
        payload={"sql": sql, "params": params or {}},
        metadata=metadata or {},
    )

    # Honor a prior human approval (single-use, claimed atomically).
    claimed = _claim_approval(db, approval_id, agent, resource, action_type)
    auth = authorize_action(db, agent, req, pre_approved=claimed)
    if auth.decision.decision != Decision.ALLOW:
        if claimed:  # action won't run — don't burn the human sign-off
            _restore_approval(db, approval_id, agent, resource, action_type)
        return QueryResult(
            executed=False, decision=auth.decision,
            audit_record=auth.audit_record, approval=auth.approval,
        )

    # Permitted — run it against the vaulted DSN and redact the results.
    dsn = decrypt_secret(connector.auth_secret_encrypted)
    try:
        columns, rows = _run_query(dsn, sql, params or {})
    except SQLAlchemyError as exc:
        msg = str(getattr(exc, "orig", exc))
        ledger.append(
            agent_id=agent.id, agent_name=agent.name,
            role_name=agent.role.name if agent.role else "",
            action_type=f"{action_type}.result", resource=resource,
            decision=Decision.DENY, reason=f"Query failed: {msg}", billable=False,
            org_id=agent.org_id,
        )
        return QueryResult(
            executed=False, decision=auth.decision,
            audit_record=auth.audit_record, error=msg,
        )

    scan = scan_payload(rows)
    redacted_rows = scan.redacted if scan.has_findings else rows
    findings = scan.findings_as_dicts()

    ledger.append(
        agent_id=agent.id, agent_name=agent.name,
        role_name=agent.role.name if agent.role else "",
        action_type=f"{action_type}.result", resource=resource,
        decision=Decision.ALLOW,
        reason=f"Query returned {len(rows)} row(s)"
        + (f"; {len(findings)} DLP finding(s) redacted" if findings else ""),
        payload_hash=payload_fingerprint(rows),
        payload_preview=build_preview(redacted_rows),
        dlp_findings=findings,
        billable=False, org_id=agent.org_id,
    )

    return QueryResult(
        executed=True,
        decision=auth.decision,
        audit_record=auth.audit_record,
        columns=columns,
        rows=redacted_rows,
        row_count=len(rows),
        response_dlp_findings=findings,
    )


def execute_write(
    db: Session,
    agent: Agent,
    *,
    connector_name: str,
    sql: str,
    params: dict | None = None,
    metadata: dict | None = None,
    approval_id: int | None = None,
) -> QueryResult:
    """Governed write (INSERT/UPDATE/DELETE) against a *writable* DB connector.

    The plane holds the DSN; the write runs in a transaction and is rolled back
    if it would affect more rows than the connector's cap. Policy (incl. approval)
    is enforced before anything touches the database.
    """
    connector = db.scalar(
        select(Connector).where(
            Connector.name == connector_name, Connector.org_id == agent.org_id
        )
    )
    if not connector or not connector.enabled:
        raise ValueError(f"unknown or disabled connector '{connector_name}'")
    if connector.kind != "database":
        raise ValueError(f"connector '{connector_name}' is not a database connector")

    resource = f"db:{connector_name}"
    ledger = AuditLedger(db)

    def _deny(reason: str, action_type: str, affected: int = 0) -> QueryResult:
        rec = ledger.append(
            agent_id=agent.id, agent_name=agent.name,
            role_name=agent.role.name if agent.role else "",
            action_type=action_type, resource=resource,
            decision=Decision.DENY, reason=reason, payload_preview=build_preview(sql),
            billable=False, org_id=agent.org_id,
        )
        return QueryResult(executed=False, decision=PolicyDecision(Decision.DENY, reason),
                           audit_record=rec, error=reason, row_count=affected)

    # Defense in depth: writes only on connectors explicitly marked writable.
    if not connector.writable:
        return _deny("connector is read-only (writes are disabled)", "db.write")

    verb, err = _classify_write(sql)
    action_type = f"db.{verb.lower()}" if verb else "db.write"
    if err is not None:
        return _deny(f"Write rejected: {err}", action_type)

    req = ActionRequest(
        action_type=action_type, resource=resource,
        payload={"sql": sql, "params": params or {}}, metadata=metadata or {},
    )

    claimed = _claim_approval(db, approval_id, agent, resource, action_type)
    auth = authorize_action(db, agent, req, pre_approved=claimed)
    if auth.decision.decision != Decision.ALLOW:
        if claimed:  # action won't run — don't burn the human sign-off
            _restore_approval(db, approval_id, agent, resource, action_type)
        return QueryResult(executed=False, decision=auth.decision,
                           audit_record=auth.audit_record, approval=auth.approval)

    dsn = decrypt_secret(connector.auth_secret_encrypted)
    try:
        affected, capped = _run_write(dsn, sql, params or {}, connector.max_write_rows)
    except SQLAlchemyError as exc:
        msg = str(getattr(exc, "orig", exc))
        ledger.append(
            agent_id=agent.id, agent_name=agent.name,
            role_name=agent.role.name if agent.role else "",
            action_type=f"{action_type}.result", resource=resource,
            decision=Decision.DENY, reason=f"Write failed: {msg}", billable=False,
            org_id=agent.org_id,
        )
        return QueryResult(executed=False, decision=auth.decision,
                           audit_record=auth.audit_record, error=msg)

    if capped:
        reason = (
            f"Write rolled back: would affect {affected} rows, exceeds the "
            f"connector cap of {connector.max_write_rows}"
        )
        ledger.append(
            agent_id=agent.id, agent_name=agent.name,
            role_name=agent.role.name if agent.role else "",
            action_type=f"{action_type}.result", resource=resource,
            decision=Decision.DENY, reason=reason, billable=False, org_id=agent.org_id,
        )
        return QueryResult(executed=False, decision=PolicyDecision(Decision.DENY, reason),
                           audit_record=auth.audit_record, error=reason, row_count=affected)

    ledger.append(
        agent_id=agent.id, agent_name=agent.name,
        role_name=agent.role.name if agent.role else "",
        action_type=f"{action_type}.result", resource=resource,
        decision=Decision.ALLOW, reason=f"Write committed; {affected} row(s) affected",
        billable=False, org_id=agent.org_id,
    )
    return QueryResult(executed=True, decision=auth.decision,
                       audit_record=auth.audit_record, row_count=affected)
