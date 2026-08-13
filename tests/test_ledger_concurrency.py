"""Concurrency regressions for the append-only ledger.

These cover a *verified* defect, not a hypothetical one. Under the previous
optimistic scheme (read head -> insert -> absorb UNIQUE violation -> retry),
12 threads x 20 appends permanently lost 8 records after exhausting the retry
budget — and ``verify_chain`` still reported ``valid=True``, because a hash
chain cannot detect rows that were never written.
"""

from __future__ import annotations

import threading

from agentguard.audit.ledger import AuditLedger, verify_chain
from agentguard.database import SessionLocal
from agentguard.models import AuditRecord


def _append(db, name: str) -> None:
    AuditLedger(db).append(
        agent_id=None, agent_name=name, role_name="r",
        action_type="tool.call", resource="x", decision="allow", reason="t",
    )


def test_concurrent_appends_never_drop_a_record():
    """Every accepted append must end up in the chain — no silent audit gap."""
    threads, per_thread = 12, 15
    failures: list[str] = []
    committed = threading.Semaphore(0)

    def worker(n: int) -> None:
        for _ in range(per_thread):
            session = SessionLocal()
            try:
                _append(session, f"agent-{n}")
                committed.release()
            except Exception as exc:  # noqa: BLE001 - the point of the test
                failures.append(f"{type(exc).__name__}: {exc}")
            finally:
                session.close()

    workers = [threading.Thread(target=worker, args=(n,)) for n in range(threads)]
    for t in workers:
        t.start()
    for t in workers:
        t.join()

    assert failures == [], f"appends were dropped: {failures[:3]}"

    db = SessionLocal()
    try:
        status = verify_chain(db)
        assert status.valid is True, status.detail
        # The chain must actually contain every record, not merely be internally
        # consistent — an intact-but-short chain is the failure mode being tested.
        assert status.length == threads * per_thread
    finally:
        db.close()


def test_concurrent_appends_produce_a_gapless_sequence():
    """seq must be a dense 0..n-1 range; a gap means a lost link."""
    threads, per_thread = 8, 10

    def worker(n: int) -> None:
        session = SessionLocal()
        try:
            for _ in range(per_thread):
                _append(session, f"agent-{n}")
        finally:
            session.close()

    workers = [threading.Thread(target=worker, args=(n,)) for n in range(threads)]
    for t in workers:
        t.start()
    for t in workers:
        t.join()

    db = SessionLocal()
    try:
        seqs = sorted(r.seq for r in db.query(AuditRecord).all())
        assert seqs == list(range(threads * per_thread))
    finally:
        db.close()


def test_anchor_head_uses_max_seq_not_last_line(tmp_path, monkeypatch):
    """Anchoring happens outside the append lock, so file order is not seq order."""
    from agentguard import config
    from agentguard.audit import ledger as ledger_mod

    anchor = tmp_path / "anchor.log"
    # Deliberately out of order: the highest seq is NOT the last line.
    anchor.write_text("5\taaa\n9\tbbb\n7\tccc\n", encoding="utf-8")

    settings = config.get_settings()
    monkeypatch.setattr(settings, "audit_anchor_path", str(anchor))

    assert ledger_mod._read_anchor_head() == (9, "bbb")


def test_anchor_head_skips_torn_lines(tmp_path, monkeypatch):
    """A partially-written line must not make the truncation check fail open."""
    from agentguard import config
    from agentguard.audit import ledger as ledger_mod

    anchor = tmp_path / "anchor.log"
    anchor.write_text("3\taaa\ngarbage-no-tab\n4\tbbb\n", encoding="utf-8")

    settings = config.get_settings()
    monkeypatch.setattr(settings, "audit_anchor_path", str(anchor))

    assert ledger_mod._read_anchor_head() == (4, "bbb")
