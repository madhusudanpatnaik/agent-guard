"""Tests for the pluggable rate/quota counter backends."""

import time

from agentops.counters import DBRateBackend, RedisRateBackend, get_rate_backend
from agentops.audit.ledger import AuditLedger
from agentops.models import Decision


class FakeRedis:
    """A tiny in-memory stand-in implementing the ZSET subset we use."""

    def __init__(self):
        self.sets: dict[str, dict[str, float]] = {}
        self.fail = False

    def zadd(self, key, mapping):
        if self.fail:
            raise RuntimeError("boom")
        self.sets.setdefault(key, {}).update(mapping)

    def zremrangebyscore(self, key, lo, hi):
        if self.fail:
            raise RuntimeError("boom")
        s = self.sets.get(key, {})
        for m in [m for m, sc in s.items() if lo <= sc <= hi]:
            del s[m]

    def zcount(self, key, lo, hi):
        if self.fail:
            raise RuntimeError("boom")
        return sum(1 for sc in self.sets.get(key, {}).values() if lo <= sc <= hi)

    def expire(self, key, ttl):
        if self.fail:
            raise RuntimeError("boom")


# --- DB backend (default) ---------------------------------------------------

def test_db_backend_counts_billable_only(db):
    ledger = AuditLedger(db)
    ledger.append(agent_id=7, agent_name="a", role_name="r", action_type="act",
                  resource="x", decision=Decision.ALLOW, reason="", billable=True)
    ledger.append(agent_id=7, agent_name="a", role_name="r", action_type="act.result",
                  resource="x", decision=Decision.ALLOW, reason="", billable=False)
    backend = DBRateBackend()
    assert backend.count(db, 7, 3600) == 1  # the .result row is excluded


def test_get_rate_backend_defaults_to_db(monkeypatch):
    from agentops.config import get_settings
    from agentops import counters
    monkeypatch.setattr(get_settings(), "rate_limit_backend", "db")
    counters.reset_rate_backend_cache()
    assert isinstance(get_rate_backend(), DBRateBackend)
    counters.reset_rate_backend_cache()


# --- Redis sliding window ---------------------------------------------------

def test_redis_sliding_window_counts_within_window(db):
    fake = FakeRedis()
    backend = RedisRateBackend(fake, fallback=DBRateBackend())
    # Three actions "now".
    for _ in range(3):
        backend.observe(db, 42)
    assert backend.count(db, 42, 60) == 3

    # An action far in the past is pruned out of a short window.
    old_key = backend._key(42)
    fake.sets[old_key]["stale"] = time.time() - 10_000
    assert backend.count(db, 42, 60) == 3          # 60s window excludes it
    assert backend.count(db, 42, 24 * 3600) >= 3   # wide window still bounded by prune


def test_redis_isolates_agents(db):
    fake = FakeRedis()
    backend = RedisRateBackend(fake, fallback=DBRateBackend())
    backend.observe(db, 1)
    backend.observe(db, 1)
    backend.observe(db, 2)
    assert backend.count(db, 1, 60) == 2
    assert backend.count(db, 2, 60) == 1


def test_redis_failure_falls_back_to_db(db):
    # DB has one billable action for agent 9.
    AuditLedger(db).append(agent_id=9, agent_name="a", role_name="r", action_type="act",
                           resource="x", decision=Decision.ALLOW, reason="", billable=True)
    fake = FakeRedis()
    fake.fail = True  # every Redis op raises
    backend = RedisRateBackend(fake, fallback=DBRateBackend())
    # count must transparently use the DB fallback rather than raise.
    assert backend.count(db, 9, 3600) == 1
    # observe must swallow the error (never break governance).
    backend.observe(db, 9)


def test_concurrent_same_instant_actions_all_count(db):
    fake = FakeRedis()
    backend = RedisRateBackend(fake, fallback=DBRateBackend())
    # Two observes at effectively the same timestamp must both be counted
    # (unique members), not collapse into one.
    backend.observe(db, 5)
    backend.observe(db, 5)
    assert backend.count(db, 5, 60) == 2
