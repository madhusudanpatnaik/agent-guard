"""Append-only, hash-chained audit ledger.

Every governed decision is committed as an :class:`~agentops.models.AuditRecord`
whose ``hash`` is ``SHA-256(prev_hash || canonical_json(entry))``. Because each
row commits to its predecessor, editing or deleting any historic row breaks the
chain from that point forward, and :func:`verify_chain` will pinpoint the first
divergence. This gives the "unalterable audit trail" compliance teams require —
without depending on a blockchain or an external notary.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..config import get_settings
from ..models import AuditRecord

GENESIS_HASH = "0" * 64
_DOMAIN = "agentops.ledger.v1"
_APPEND_MAX_RETRIES = 5

# Dedicated logger so operators can route the audit stream to a SIEM via standard
# log shipping (JSON per line), independent of the optional webhook.
_audit_log = logging.getLogger("agentops.audit")


def _canonical(entry: dict[str, Any]) -> str:
    """Deterministic serialization used as the hash pre-image."""
    return json.dumps(entry, sort_keys=True, separators=(",", ":"), default=str)


def record_hash(prev_hash: str, entry: dict[str, Any]) -> str:
    """Keyed (HMAC-SHA256) link commitment.

    Keying the chain with the server secret means an attacker who gains raw
    database write access still cannot silently re-forge the whole chain after a
    tampered row — they would also need the secret. A domain-separated, delimited
    pre-image removes any canonical-concatenation ambiguity.
    """
    key = get_settings().secret_key.encode()
    message = f"{_DOMAIN}\x1f{prev_hash}\x1f{_canonical(entry)}".encode()
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def _normalize_ts(dt: datetime | None) -> str | None:
    """Timezone-agnostic UTC timestamp string.

    SQLite drops tzinfo on the round-trip while Postgres preserves it, so we
    normalize to a naive-UTC ISO string on both the write and verify paths to
    keep the hash pre-image identical regardless of backend.
    """
    if dt is None:
        return None
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt.isoformat()


def _hashable_view(rec: AuditRecord) -> dict[str, Any]:
    """The subset of columns that are covered by the hash commitment."""
    return {
        "seq": rec.seq,
        "org_id": rec.org_id,
        "agent_id": rec.agent_id,
        "agent_name": rec.agent_name,
        "role_name": rec.role_name,
        "action_type": rec.action_type,
        "resource": rec.resource,
        "decision": rec.decision,
        "reason": rec.reason,
        "payload_hash": rec.payload_hash,
        "payload_preview": rec.payload_preview,
        "dlp_findings": rec.dlp_findings,
        "dlp_count": rec.dlp_count,
        "billable": rec.billable,
        "matched_policy_id": rec.matched_policy_id,
        "created_at": _normalize_ts(rec.created_at),
        "prev_hash": rec.prev_hash,
    }


@dataclass
class ChainStatus:
    valid: bool
    length: int
    head_hash: str
    broken_at_seq: int | None = None
    detail: str = "ok"

    def as_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "length": self.length,
            "head_hash": self.head_hash,
            "broken_at_seq": self.broken_at_seq,
            "detail": self.detail,
        }


# --------------------------------------------------------------------------- #
# Cached chain status
#
# A full verify_chain() re-HMACs every row — O(n) — which is fine for the
# explicit superadmin endpoint but far too heavy to run on every dashboard
# load. The cache holds the last verified status and is NEVER trusted blindly:
# every read compares it against the actual DB head, so any append, edit of the
# head, or truncation forces (at least) an incremental re-verification. Only
# an edit of a *historic* row that leaves the head untouched can hide behind
# the cache until the next full verify — which /api/audit/verify always runs.
# --------------------------------------------------------------------------- #

_cache_lock = threading.Lock()
_cached_status: ChainStatus | None = None


def _cache_get() -> ChainStatus | None:
    with _cache_lock:
        return _cached_status


def _cache_set(status: ChainStatus) -> None:
    global _cached_status
    with _cache_lock:
        _cached_status = status


def reset_chain_cache() -> None:
    """Drop the cached status (tests / after an operator ledger reset)."""
    global _cached_status
    with _cache_lock:
        _cached_status = None


def _cache_extend(rec: AuditRecord) -> None:
    """Advance the cached head for a row this process just appended.

    Only extends when the new row links exactly onto the cached head; any
    mismatch (another process appended in between, or no cache yet) simply
    leaves the cache to be refreshed by the next read.
    """
    global _cached_status
    with _cache_lock:
        cached = _cached_status
        if (
            cached is not None
            and cached.valid
            and rec.seq == cached.length
            and rec.prev_hash == cached.head_hash
        ):
            _cached_status = ChainStatus(
                valid=True, length=rec.seq + 1, head_hash=rec.hash, detail="chain intact"
            )


def chain_status(db: Session) -> ChainStatus:
    """Return the ledger's integrity status using the verified-prefix cache.

    Fast paths (no full walk):
      * DB head matches the cached head           -> cached status.
      * DB head is ahead of a valid cached prefix -> verify only the new rows.
    Anything else — no cache, a shorter chain (possible truncation), or a link
    mismatch — falls back to the full :func:`verify_chain`.
    """
    head = db.scalar(select(AuditRecord).order_by(AuditRecord.seq.desc()).limit(1))
    cached = _cache_get()

    if head is None:
        # Empty ledger: cheap to verify fully (also runs the anchor check).
        return verify_chain(db)

    if cached is not None and cached.valid:
        if head.seq + 1 == cached.length and head.hash == cached.head_hash:
            return cached
        if head.seq + 1 > cached.length:
            # Rows were appended (possibly by another process): verify just the
            # suffix, linking off the trusted cached head.
            new_rows = list(db.scalars(
                select(AuditRecord)
                .where(AuditRecord.seq >= cached.length)
                .order_by(AuditRecord.seq.asc())
            ))
            prev_hash = cached.head_hash
            expected_seq = cached.length
            ok = True
            for rec in new_rows:
                if (
                    rec.seq != expected_seq
                    or rec.prev_hash != prev_hash
                    or record_hash(prev_hash, _hashable_view(rec)) != rec.hash
                ):
                    ok = False
                    break
                prev_hash = rec.hash
                expected_seq += 1
            if ok:
                status = ChainStatus(
                    valid=True, length=expected_seq, head_hash=prev_hash,
                    detail="chain intact",
                )
                _cache_set(status)
                return status
        # Shorter chain or a bad link in the suffix — do the authoritative walk.

    return verify_chain(db)


def _anchor_head(rec: AuditRecord) -> None:
    """Anchor the new head to every configured out-of-band backend.

    Because these live outside the primary database, an attacker who can only
    write to the DB cannot delete the newest ledger rows without leaving the
    anchor ahead of the DB head — which :func:`verify_chain` then reports. The
    file backend also feeds the head-truncation check below; transparency-log
    and RFC-3161 backends add third-party-verifiable, node-loss-durable proof.
    """
    from .anchors import anchor_head

    anchor_head(rec.seq, rec.hash)


def _read_anchor_head() -> tuple[int, str] | None:
    path = get_settings().audit_anchor_path
    if not path or not Path(path).exists():
        return None
    # Take the highest seq, not the last line written: anchoring happens after
    # the commit and outside the append lock, so two concurrent appends can
    # write their anchor lines in either order. Trusting file order would let a
    # lower seq land last and silently weaken the head-truncation check.
    best: tuple[int, str] | None = None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    seq_str, h = line.split("\t")
                    seq = int(seq_str)
                except ValueError:
                    continue  # skip a torn/partial line rather than failing open
                if best is None or seq > best[0]:
                    best = (seq, h)
    except OSError:
        return None
    return best


def _emit_siem(rec: AuditRecord) -> None:
    """Emit each decision as JSON: always to the audit logger, optionally webhook."""
    event = {
        "seq": rec.seq, "hash": rec.hash, "agent": rec.agent_name, "role": rec.role_name,
        "action_type": rec.action_type, "resource": rec.resource, "decision": rec.decision,
        "reason": rec.reason, "dlp_count": rec.dlp_count,
        "created_at": _normalize_ts(rec.created_at),
    }
    _audit_log.info(json.dumps(event, default=str))

    url = get_settings().siem_webhook_url
    if not url:
        return
    # HMAC-signed when webhook_signing_secret is set; best-effort (never blocks).
    from ..webhooks import post_json

    post_json(url, event, timeout=2.0)


# --------------------------------------------------------------------------- #
# Append serialization
#
# A hash chain is *inherently serial*: every append must read the current head
# and commit to its hash, so seq N+1 cannot be built until N exists. The old
# optimistic scheme (read head -> insert -> absorb UNIQUE violation -> retry)
# does not merely waste work under concurrency, it LOSES RECORDS: with 12
# threads x 20 appends, 8 governed decisions failed permanently after exhausting
# the retries — and verify_chain still reported `valid=True`, because a chain
# cannot detect rows that were never written. That is precisely the gap an audit
# ledger exists to make impossible.
#
# The fix is to make the read-head/insert pair genuinely atomic. Note that an
# atomically-allocated sequence number would NOT be sufficient here: holding seq
# N+1 is useless until row N has committed its hash, so the serialization point
# is unavoidable — it just has to be correct rather than probabilistic.
# --------------------------------------------------------------------------- #

# Arbitrary but stable 64-bit key identifying "the AgentOps ledger" to Postgres.
# Fits in a signed bigint, which is what pg_advisory_xact_lock takes.
_ADVISORY_LOCK_KEY = 0x4147_4E54_4F50_5301

# Serializes appends within this process. On Postgres the advisory lock is what
# makes appends safe *across* workers; this one keeps a 40-thread ASGI pool from
# stampeding the database to discover that, and is the sole guard on SQLite.
_process_append_lock = threading.Lock()

# Backends that serialize across processes. Anything else gets the process lock
# only, and is warned about once at startup rather than failing silently.
_CROSS_PROCESS_DIALECTS = frozenset({"postgresql", "sqlite"})
_warned_dialects: set[str] = set()


@contextmanager
def _append_lock(db: Session) -> Iterator[None]:
    """Serialize the read-head/insert critical section across all writers.

    Postgres takes a **transaction-scoped** advisory lock, which the database
    releases automatically on COMMIT *or* ROLLBACK — so a worker that dies
    mid-append cannot wedge the ledger for the rest of the fleet.

    SQLite needs only the process lock: it is single-writer by construction and
    is the development/single-node backend.

    Other backends fall back to the process lock, which does **not** serialize
    across workers. MySQL is deliberately not special-cased here: its
    ``GET_LOCK`` is connection-scoped, and SQLAlchemy returns the connection to
    the pool on commit, so the matching ``RELEASE_LOCK`` could execute on a
    different connection and strand the lock. Shipping that untested is worse
    than declining to claim support, so the limitation is surfaced instead.
    """
    with _process_append_lock:
        dialect = db.get_bind().dialect.name
        if dialect == "postgresql":
            # This also begins the transaction the INSERT runs in, which is what
            # makes one lock cover the whole critical section.
            db.execute(text("SELECT pg_advisory_xact_lock(:key)"),
                       {"key": _ADVISORY_LOCK_KEY})
        elif dialect not in _CROSS_PROCESS_DIALECTS and dialect not in _warned_dialects:
            _warned_dialects.add(dialect)
            _audit_log.warning(json.dumps({
                "event": "LEDGER_APPEND_LOCK_DEGRADED",
                "dialect": dialect,
                "detail": ("no cross-process append serialization for this backend; "
                           "run a single worker or use PostgreSQL"),
            }))
        yield


def _emit_append_failure(entry: dict[str, Any], error: BaseException) -> None:
    """Record an append that could not be persisted, out-of-band.

    Some call sites append *after* the governed action already hit the upstream
    system, so a lost append means a real side effect with no ledger row — and
    the chain cannot flag its own absence. Emitting to the audit log stream at
    ERROR keeps the gap visible to the SIEM even when the database refused it.
    """
    _audit_log.error(json.dumps({
        "event": "LEDGER_APPEND_FAILED",
        "error": f"{type(error).__name__}: {error}",
        "agent": entry.get("agent_name"),
        "role": entry.get("role_name"),
        "action_type": entry.get("action_type"),
        "resource": entry.get("resource"),
        "decision": entry.get("decision"),
        "reason": entry.get("reason"),
    }, default=str))


class AuditLedger:
    """Thin persistence helper around :class:`AuditRecord`."""

    def __init__(self, db: Session):
        self.db = db

    def _head(self) -> AuditRecord | None:
        return self.db.scalar(select(AuditRecord).order_by(AuditRecord.seq.desc()).limit(1))

    def append(
        self,
        *,
        agent_id: int | None,
        agent_name: str,
        role_name: str,
        action_type: str,
        resource: str,
        decision: str,
        reason: str,
        payload_hash: str = "",
        payload_preview: str = "",
        dlp_findings: list | None = None,
        matched_policy_id: int | None = None,
        billable: bool = True,
        org_id: int | None = None,
        risk_score: int = 0,
        risk_factors: list | None = None,
    ) -> AuditRecord:
        fields = dict(
            org_id=org_id, agent_id=agent_id, agent_name=agent_name,
            role_name=role_name, action_type=action_type, resource=resource,
            decision=decision, reason=reason, payload_hash=payload_hash,
            payload_preview=payload_preview, dlp_findings=dlp_findings or [],
            dlp_count=len(dlp_findings or []), billable=billable,
            matched_policy_id=matched_policy_id,
            # Risk is recorded but excluded from the hash pre-image.
            risk_score=risk_score, risk_factors=risk_factors or [],
        )

        # Reading the head and inserting the row that links to it must be one
        # atomic step (see _append_lock). The retry loop is kept as a backstop
        # for the fallback path and for transient DB errors; with the lock held
        # the UNIQUE(seq) violation should no longer be reachable.
        rec: AuditRecord | None = None
        for attempt in range(_APPEND_MAX_RETRIES):
            try:
                with _append_lock(self.db):
                    head = self._head()
                    prev_hash = GENESIS_HASH if head is None else head.hash
                    rec = AuditRecord(
                        seq=0 if head is None else head.seq + 1,
                        prev_hash=prev_hash,
                        created_at=datetime.now(timezone.utc),
                        **fields,
                    )
                    rec.hash = record_hash(prev_hash, _hashable_view(rec))
                    self.db.add(rec)
                    self.db.commit()
                break
            except IntegrityError as exc:
                self.db.rollback()
                rec = None
                if attempt == _APPEND_MAX_RETRIES - 1:
                    # The action may already have taken effect upstream, and a
                    # missing row is invisible to verify_chain — so make the gap
                    # loud rather than letting it vanish with the exception.
                    _emit_append_failure(fields, exc)
                    raise

        if rec is None:  # pragma: no cover - loop either breaks or raises
            raise RuntimeError("ledger append exhausted retries without resolving")

        self.db.refresh(rec)

        # Anchor the new head out-of-band + stream to SIEM (both best-effort),
        # and advance the verified-prefix cache to the new head. Deliberately
        # OUTSIDE the append lock: these do network and filesystem I/O, and
        # holding a global serialization point across a webhook POST would make
        # every append in the fleet wait on one HTTP round-trip.
        _anchor_head(rec)
        _emit_siem(rec)
        _cache_extend(rec)
        return rec

    def count(self) -> int:
        return self.db.scalar(select(func.count(AuditRecord.id))) or 0

    def verify(self) -> ChainStatus:
        return verify_chain(self.db)


def verify_chain(db: Session) -> ChainStatus:
    """Walk the whole ledger and confirm every link is intact.

    Beyond the in-DB hash chain (which catches edits and mid-chain deletions),
    this also compares the DB head against the out-of-band anchor to catch a
    head *truncation* — deleting the newest rows — which an intact-but-shorter
    chain would otherwise hide. The result seeds the verified-prefix cache used
    by :func:`chain_status`.
    """
    status = _verify_chain_full(db)
    _cache_set(status)
    return status


_VERIFY_BATCH = 1000


def _verify_chain_full(db: Session) -> ChainStatus:
    """Walk the entire chain in bounded memory.

    The ledger is the one table that grows without limit, so materializing it
    (``list(db.scalars(...))``) would make an integrity check cost O(table) RAM —
    at tens of millions of rows that is an OOM kill triggered by an API call.
    Rows are streamed in batches instead, so memory stays O(batch) no matter how
    long the chain is. The head/length are read up front with two cheap indexed
    queries so failure reports still carry them.
    """
    anchor = _read_anchor_head()
    head = db.scalar(select(AuditRecord).order_by(AuditRecord.seq.desc()).limit(1))

    if head is None:
        if anchor is not None:
            return ChainStatus(
                valid=False, length=0, head_hash=GENESIS_HASH, broken_at_seq=0,
                detail=f"ledger truncated: anchor expects head seq {anchor[0]} but DB is empty",
            )
        return ChainStatus(valid=True, length=0, head_hash=GENESIS_HASH, detail="empty ledger")

    total = db.scalar(select(func.count(AuditRecord.id))) or 0
    head_hash = head.hash

    def _broken(seq: int, detail: str) -> ChainStatus:
        return ChainStatus(valid=False, length=total, head_hash=head_hash,
                           broken_at_seq=seq, detail=detail)

    prev_hash = GENESIS_HASH
    expected_seq = 0
    # yield_per streams server-side in batches instead of buffering the result.
    stream = db.scalars(
        select(AuditRecord).order_by(AuditRecord.seq.asc()).execution_options(
            yield_per=_VERIFY_BATCH)
    )
    for rec in stream:
        if rec.seq != expected_seq:
            return _broken(rec.seq, f"sequence gap: expected {expected_seq}, found {rec.seq}")
        if rec.prev_hash != prev_hash:
            return _broken(rec.seq, f"prev_hash mismatch at seq {rec.seq}")
        if record_hash(prev_hash, _hashable_view(rec)) != rec.hash:
            return _broken(rec.seq, f"hash mismatch at seq {rec.seq} (row was tampered with)")
        prev_hash = rec.hash
        expected_seq += 1
        # Detach the verified row so the identity map doesn't accumulate the
        # whole table across batches (which would defeat the streaming).
        db.expunge(rec)
    # Head-truncation check: the anchor must not be ahead of the DB head.
    if anchor is not None and anchor[0] > head.seq:
        return ChainStatus(
            valid=False,
            length=total,
            head_hash=head_hash,
            broken_at_seq=head.seq + 1,
            detail=(
                f"ledger truncated: anchor expects head seq {anchor[0]} "
                f"but DB head is seq {head.seq}"
            ),
        )

    return ChainStatus(
        valid=True,
        length=total,
        head_hash=head_hash,
        detail="chain intact",
    )
