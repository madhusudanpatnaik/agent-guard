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

import hashlib
import threading
from dataclasses import dataclass, field

from sqlalchemy import create_engine, select, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from . import sql_guard
from .audit.ledger import AuditLedger
from .config import get_settings
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


def _classify(sql: str, dialect: str | None = None) -> tuple[str, str | None]:
    """Return ``(verb, error)`` for a READ, decided on the parsed AST.

    Delegates to :mod:`agentguard.sql_guard`, which reasons over SQLGlot nodes
    instead of text — so comment-splitting, nesting, and data-modifying CTEs
    (all of which defeated the previous string classifier) are caught
    structurally.
    """
    analysis = sql_guard.analyze(sql, dialect=dialect, read_only=True)
    return (analysis.verb or ""), analysis.error


def _classify_write(sql: str, dialect: str | None = None) -> tuple[str, str | None]:
    """Return ``(verb, error)`` for a WRITE, decided on the parsed AST."""
    analysis = sql_guard.analyze(sql, dialect=dialect, read_only=False)
    return (analysis.verb or ""), analysis.error


# --------------------------------------------------------------------------- #
# Engine cache
#
# Building a SQLAlchemy engine and disposing it per query means a full TCP (and
# TLS) connect + teardown on EVERY governed statement — hundreds of milliseconds
# against a remote Postgres, and a steady supply of TIME_WAIT sockets under load.
# Engines are therefore cached and reused; the cache key includes a digest of the
# DSN so rotating a connector's vaulted secret transparently yields a NEW engine
# rather than silently reusing a connection opened with the old credentials.
# --------------------------------------------------------------------------- #

_engine_cache: dict[str, Engine] = {}
_engine_lock = threading.Lock()


def _engine_for(dsn: str) -> Engine:
    key = hashlib.sha256(dsn.encode()).hexdigest()
    with _engine_lock:
        engine = _engine_cache.get(key)
        if engine is not None:
            return engine

    settings = get_settings()
    kwargs: dict = {}
    if not dsn.startswith("sqlite"):
        kwargs = {
            "pool_size": settings.connector_pool_size,
            "max_overflow": settings.connector_max_overflow,
            "pool_timeout": settings.db_pool_timeout,
            "pool_recycle": settings.db_pool_recycle,
        }
    engine = create_engine(dsn, pool_pre_ping=True, **kwargs)

    with _engine_lock:
        # Another thread may have built one concurrently; keep a single instance
        # and dispose the loser so we never leak a pool.
        existing = _engine_cache.get(key)
        if existing is not None:
            engine.dispose()
            return existing
        _engine_cache[key] = engine
        return engine


def reset_engine_cache() -> None:
    """Dispose and drop all cached connector engines (tests / shutdown)."""
    with _engine_lock:
        for engine in _engine_cache.values():
            engine.dispose()
        _engine_cache.clear()


def _run_query(dsn: str, sql: str, params: dict) -> tuple[list[str], list[dict]]:
    engine = _engine_for(dsn)  # pooled + reused; never disposed per query
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
            # A pooled SQLite connection keeps PRAGMA state across checkouts;
            # clear it so a later governed WRITE on the same pool isn't blocked.
            if engine.dialect.name == "sqlite":
                conn.exec_driver_sql("PRAGMA query_only = OFF")
    return columns, rows


def _run_write(dsn: str, sql: str, params: dict, max_rows: int) -> tuple[int, bool]:
    """Execute a write in a transaction. Returns ``(rows_affected, capped)``.

    If the statement would affect more than ``max_rows``, the transaction is
    **rolled back** and ``capped`` is True — nothing is persisted.
    """
    engine = _engine_for(dsn)  # pooled + reused; never disposed per query
    with engine.connect() as conn:
        trans = conn.begin()
        result = conn.execute(text(sql), params or {})
        affected = result.rowcount
        if affected is not None and affected >= 0 and affected > max_rows:
            trans.rollback()
            return affected, True
        trans.commit()
        return (affected if affected is not None and affected >= 0 else 0), False


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

    dsn = decrypt_secret(connector.auth_secret_encrypted)
    verb, err = _classify(sql, sql_guard._dialect_for(dsn))
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

    dsn = decrypt_secret(connector.auth_secret_encrypted)
    verb, err = _classify_write(sql, sql_guard._dialect_for(dsn))
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
