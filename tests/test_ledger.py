"""Unit tests for the tamper-evident audit ledger."""

from agentops.audit.ledger import (
    AuditLedger,
    _cache_get,
    _cache_set,
    chain_status,
    reset_chain_cache,
    verify_chain,
)
from agentops.models import Decision


def _append(ledger, i, decision=Decision.ALLOW):
    return ledger.append(
        agent_id=1,
        agent_name=f"agent-{i}",
        role_name="role",
        action_type="db.read",
        resource=f"db:customers:{i}",
        decision=decision,
        reason="test",
    )


def test_chain_grows_and_links(db):
    ledger = AuditLedger(db)
    r0 = _append(ledger, 0)
    r1 = _append(ledger, 1)
    r2 = _append(ledger, 2)
    assert (r0.seq, r1.seq, r2.seq) == (0, 1, 2)
    assert r1.prev_hash == r0.hash
    assert r2.prev_hash == r1.hash


def test_empty_ledger_is_valid(db):
    status = verify_chain(db)
    assert status.valid is True
    assert status.length == 0


def test_intact_chain_verifies(db):
    ledger = AuditLedger(db)
    for i in range(5):
        _append(ledger, i)
    status = verify_chain(db)
    assert status.valid is True
    assert status.length == 5


def test_tampering_a_row_breaks_the_chain(db):
    ledger = AuditLedger(db)
    for i in range(5):
        _append(ledger, i)

    # Simulate a malicious after-the-fact edit of a historic row's content.
    from agentops.models import AuditRecord

    victim = db.query(AuditRecord).filter(AuditRecord.seq == 2).one()
    victim.reason = "tampered — this action was actually denied"
    db.commit()

    status = verify_chain(db)
    assert status.valid is False
    assert status.broken_at_seq == 2


def test_deleting_a_row_breaks_sequence(db):
    ledger = AuditLedger(db)
    for i in range(4):
        _append(ledger, i)

    from agentops.models import AuditRecord

    db.query(AuditRecord).filter(AuditRecord.seq == 1).delete()
    db.commit()

    status = verify_chain(db)
    assert status.valid is False
    assert status.broken_at_seq == 2  # first gap after the deleted seq 1


# --------------------------------------------------------------------------- #
# Cached chain status (the dashboard's fast path)
# --------------------------------------------------------------------------- #

def test_chain_status_matches_full_verify_and_caches(db):
    ledger = AuditLedger(db)
    for i in range(3):
        _append(ledger, i)
    reset_chain_cache()

    status = chain_status(db)  # cold: falls back to the full walk
    assert status.valid is True
    assert status.length == 3
    assert status.as_dict() == verify_chain(db).as_dict()
    assert _cache_get() is not None  # the walk seeded the cache

    again = chain_status(db)  # warm: head matches -> cached object
    assert again.valid is True and again.length == 3


def test_append_extends_the_cache_in_process(db):
    ledger = AuditLedger(db)
    _append(ledger, 0)
    verify_chain(db)  # seed the cache at length 1
    rec = _append(ledger, 1)  # append() must advance the cached head

    cached = _cache_get()
    assert cached is not None and cached.valid
    assert cached.length == 2
    assert cached.head_hash == rec.hash


def test_chain_status_verifies_suffix_appended_by_another_process(db):
    ledger = AuditLedger(db)
    _append(ledger, 0)
    _append(ledger, 1)
    older = verify_chain(db)  # a valid prefix of length 2

    _append(ledger, 2)
    _append(ledger, 3)
    _cache_set(older)  # pretend the 2 new rows came from another process

    status = chain_status(db)  # must verify ONLY the suffix and extend
    assert status.valid is True
    assert status.length == 4
    cached = _cache_get()
    assert cached is not None and cached.length == 4


def test_chain_status_falls_back_on_tampered_suffix(db):
    ledger = AuditLedger(db)
    _append(ledger, 0)
    older = verify_chain(db)

    victim = _append(ledger, 1)
    victim.reason = "tampered"
    db.commit()
    _cache_set(older)  # stale prefix; the new row beyond it is corrupt

    status = chain_status(db)  # suffix check fails -> full walk -> invalid
    assert status.valid is False
    assert status.broken_at_seq == 1


def test_chain_status_shorter_chain_triggers_full_verify(db):
    ledger = AuditLedger(db)
    for i in range(4):
        _append(ledger, i)
    verify_chain(db)  # cache at length 4

    from agentops.models import AuditRecord

    db.query(AuditRecord).filter(AuditRecord.seq >= 2).delete()
    db.commit()

    # Head is now BEHIND the cache -> never trust it; re-walk from scratch.
    status = chain_status(db)
    assert status.length == 2  # reflects the DB, not the stale cache


def test_chain_status_empty_ledger(db):
    reset_chain_cache()
    status = chain_status(db)
    assert status.valid is True
    assert status.length == 0


def test_verification_streams_and_does_not_materialize_the_table(db):
    """Chain verification must be O(batch) memory, not O(table).

    Guards the OOM vector: loading every AuditRecord into a list means an
    integrity check on a large ledger kills the process.
    """
    ledger = AuditLedger(db)
    for i in range(120):
        _append(ledger, i)
    db.expunge_all()

    status = verify_chain(db)
    assert status.valid is True
    assert status.length == 120
    # The verifier expunges each row after checking it, so the session's
    # identity map must NOT be holding the whole chain afterwards.
    assert len(db.identity_map) < 50, (
        f"{len(db.identity_map)} rows retained — verification is materializing "
        "the table instead of streaming it")
