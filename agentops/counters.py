"""Pluggable rate / quota counters.

The gateway evaluates two rolling counts on every request: the per-agent quota
(over ``quota_window_seconds``) and any per-policy ``rate_limit``. By default
both derive from ``COUNT(*)`` over the audit ledger — correct and zero-infra,
but an aggregate query per request that becomes a hot spot at thousands of
requests/second.

This module abstracts that behind :class:`RateBackend` so a deployment can swap
in a **Redis sorted-set sliding window** for sub-millisecond evaluation shared
across horizontally scaled gateway nodes, without changing any calling code.

* ``db``    — :class:`DBRateBackend` (default): the ledger is the source of
  truth; ``observe`` is a no-op because the append already recorded the action.
* ``redis`` — :class:`RedisRateBackend`: maintains one sorted set per agent of
  billable-action timestamps; ``count`` is an O(log N) ``ZCOUNT`` over the
  window and ``observe`` is a ``ZADD``. Falls back to the DB backend if the
  ``redis`` package or the server is unavailable, so enabling it can never take
  governance down.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta, timezone
from functools import lru_cache

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .config import get_settings
from .models import AuditRecord

_log = logging.getLogger("agentops.counters")


class RateBackend:
    """Interface for rolling per-agent action counters."""

    def count(self, db: Session, agent_id: int, window_seconds: int) -> int:
        """Billable actions by ``agent_id`` within the trailing window."""
        raise NotImplementedError

    def observe(self, db: Session, agent_id: int) -> None:
        """Record one billable action. Backends deriving from the DB no-op."""

    def name(self) -> str:
        return type(self).__name__


class DBRateBackend(RateBackend):
    """Counts billable actions straight from the append-only ledger."""

    def count(self, db: Session, agent_id: int, window_seconds: int) -> int:
        since = datetime.now(timezone.utc) - timedelta(seconds=window_seconds)
        return (
            db.scalar(
                select(func.count(AuditRecord.id)).where(
                    AuditRecord.agent_id == agent_id,
                    AuditRecord.created_at >= since,
                    AuditRecord.billable.is_(True),
                )
            )
            or 0
        )

    # observe: the ledger append IS the record — nothing extra to do.


class RedisRateBackend(RateBackend):
    """Redis sorted-set sliding window: ``ZADD`` on observe, ``ZCOUNT`` on read.

    One key per agent (``{prefix}:{agent_id}``) holds ``score = unix_ts`` members.
    Reads prune expired members first so a key can serve arbitrary windows (the
    quota window and any per-policy rate window) from the same series. A key TTL
    bounds memory for agents that go quiet. All calls degrade to the injected
    DB fallback on any Redis error — governance must never depend on the cache.
    """

    def __init__(self, client, *, fallback: RateBackend, key_prefix: str = "aops:rate",
                 max_window_seconds: int = 24 * 3600):
        self._r = client
        self._fallback = fallback
        self._prefix = key_prefix
        self._max_window = max_window_seconds

    def _key(self, agent_id: int) -> str:
        return f"{self._prefix}:{agent_id}"

    def count(self, db: Session, agent_id: int, window_seconds: int) -> int:
        now = time.time()
        key = self._key(agent_id)
        try:
            # Prune everything older than the largest window we care about, then
            # count only the requested window — cheap and keeps the set bounded.
            self._r.zremrangebyscore(key, 0, now - self._max_window)
            return int(self._r.zcount(key, now - window_seconds, now))
        except Exception as exc:  # noqa: BLE001 — any client/server failure
            _log.warning("redis count failed (%s); using DB fallback", exc)
            return self._fallback.count(db, agent_id, window_seconds)

    def observe(self, db: Session, agent_id: int) -> None:
        now = time.time()
        key = self._key(agent_id)
        try:
            # Member must be unique so concurrent same-millisecond actions both
            # count; a monotonic-ish token keyed by time+counter suffices.
            member = f"{now:.6f}:{self._next_seq()}"
            self._r.zadd(key, {member: now})
            self._r.expire(key, self._max_window)
        except Exception as exc:  # noqa: BLE001
            _log.warning("redis observe failed (%s); rate data may under-count", exc)

    _seq = 0

    @classmethod
    def _next_seq(cls) -> int:
        cls._seq = (cls._seq + 1) % 1_000_000
        return cls._seq


@lru_cache
def get_rate_backend() -> RateBackend:
    """Build the configured backend once (cached).

    ``redis`` requires ``redis_url`` and the ``redis`` package; if either is
    missing we log and fall back to the DB backend so a misconfiguration
    degrades to "correct but slower", never to "down".
    """
    settings = get_settings()
    db_backend = DBRateBackend()
    backend = (settings.rate_limit_backend or "db").lower()
    if backend == "db":
        return db_backend
    if backend == "redis":
        if not settings.redis_url:
            _log.warning("rate_limit_backend=redis but redis_url is empty; using DB backend")
            return db_backend
        try:
            import redis
        except ImportError:
            _log.warning("rate_limit_backend=redis but the 'redis' package is not installed; "
                         "using DB backend")
            return db_backend
        client = redis.Redis.from_url(settings.redis_url, socket_timeout=0.25,
                                      socket_connect_timeout=0.25)
        _log.info("rate/quota counters: Redis sliding window at %s", settings.redis_url)
        return RedisRateBackend(client, fallback=db_backend)
    _log.warning("unknown rate_limit_backend %r; using DB backend", backend)
    return db_backend


def reset_rate_backend_cache() -> None:
    """Drop the cached backend (tests / after a settings change)."""
    get_rate_backend.cache_clear()
