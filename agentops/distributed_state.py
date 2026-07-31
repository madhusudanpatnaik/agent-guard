"""Redis-backed alternatives to three pieces of process-local state.

``counters.py`` already solved this problem once, for rate/quota counting: a
plain Python dict is correct for one process, and silently wrong the moment a
deployment runs more than one worker or replica — each one enforces its own
private view of the world. This module applies the same fix, and the same
philosophy (best-effort, degrade to the in-process behavior on any Redis
error, never let a cache backend be able to block governance), to three more
process-local stores that had never gotten it:

* the per-connector **circuit breaker** in ``resilience.py`` — "N failures ->
  open" was really "N failures per worker";
* the **DLP custom-detector cache** in ``gateway_service.py`` — a newly added
  detector took effect immediately only on the worker that received the
  write, up to ``_DETECTOR_TTL_SECONDS`` late on every other one;
* the **alert dispatch throttle** in ``alerts_service.py`` — dedup was really
  per-worker dedup, so a fleet of N workers could each send one notification
  for the same event.

None of these need Redis transactions or Lua: like ``RedisRateBackend``, they
accept a small race window in exchange for staying simple and easy to reason
about, matching the risk this codebase already accepts elsewhere for
best-effort shared state. A circuit breaker opening one call late, or two
workers each winning a HALF_OPEN trial, is a self-correcting cosmetic
imperfection — not a security property.
"""

from __future__ import annotations

import logging
import time
from functools import lru_cache
from typing import Callable

from .config import get_settings

_log = logging.getLogger("agentops.distributed_state")


@lru_cache
def get_client():
    """Resolve a shared Redis client, or None if unconfigured/unavailable.

    Cached like ``counters.get_rate_backend`` so this isn't a fresh connection
    resolution on every call; ``reset_distributed_state_cache()`` drops it for
    tests or after a settings change.
    """
    settings = get_settings()
    if (settings.distributed_state_backend or "memory").lower() != "redis":
        return None
    if not settings.redis_url:
        _log.warning(
            "distributed_state_backend=redis but redis_url is empty; using in-process state"
        )
        return None
    try:
        import redis
    except ImportError:
        _log.warning(
            "distributed_state_backend=redis but the 'redis' package is not installed; "
            "using in-process state"
        )
        return None
    # decode_responses=True: unlike counters.py's sorted sets (numeric scores
    # only), this module reads back string state ("open"/"closed"/...), so
    # raw bytes would need decoding at every call site instead of once here.
    return redis.Redis.from_url(
        settings.redis_url, socket_timeout=0.25, socket_connect_timeout=0.25,
        decode_responses=True,
    )


def reset_distributed_state_cache() -> None:
    """Drop the cached client (tests / after a settings change)."""
    get_client.cache_clear()


# --------------------------------------------------------------------------- #
# Circuit breaker
# --------------------------------------------------------------------------- #

class RedisCircuitBreaker:
    """Same three-method interface as resilience.CircuitBreaker (allow /
    record_success / record_failure), state kept in one Redis hash per
    connector instead of a per-process object, so every worker/replica
    enforces the same "N failures -> open" against the same upstream.

    wall_clock is injectable for tests, and must be a WALL clock (time.time),
    not resilience.CircuitBreaker's time.monotonic default — a monotonic
    clock's epoch is arbitrary per-process, meaningless once opened_at is
    read back by a different process than the one that wrote it.
    """

    def __init__(self, client, name: str, *, fail_threshold: int, cooldown_seconds: float,
                 fallback, wall_clock: Callable[[], float] = time.time,
                 key_prefix: str = "aops:breaker"):
        self._r = client
        self.name = name
        self.fail_threshold = fail_threshold
        self.cooldown = cooldown_seconds
        self._fallback = fallback
        self._clock = wall_clock
        self._key = f"{key_prefix}:{name}"
        # Bounds memory for a connector that goes quiet; comfortably longer
        # than any reasonable cooldown so a live breaker's state never expires
        # out from under it mid-cooldown.
        self._ttl = max(int(cooldown_seconds * 4), 60)

    def allow(self) -> bool:
        try:
            data = self._r.hgetall(self._key)
            state = data.get("state", "closed")
            if state != "open":
                return True
            opened_at = float(data.get("opened_at") or 0)
            if self._clock() - opened_at >= self.cooldown:
                self._r.hset(self._key, "state", "half_open")
                self._r.expire(self._key, self._ttl)
                return True
            return False
        except Exception as exc:  # noqa: BLE001 — resilience infra must not itself be fragile
            _log.warning("redis breaker allow() failed for %s (%s); using in-process fallback",
                        self.name, exc)
            return self._fallback.allow()

    def record_success(self) -> None:
        try:
            self._r.hset(self._key, mapping={"state": "closed", "failures": 0, "opened_at": ""})
            self._r.expire(self._key, self._ttl)
        except Exception as exc:  # noqa: BLE001
            _log.warning("redis breaker record_success() failed for %s (%s); using in-process "
                        "fallback", self.name, exc)
            self._fallback.record_success()

    def record_failure(self) -> None:
        try:
            # HINCRBY is atomic on its own — the failure count itself can never
            # be lost or double-counted under concurrent callers. The state
            # read + conditional write after it is not transactional with the
            # increment, but two workers racing here both land on the same
            # correct outcome (open) or a harmlessly-idempotent no-op.
            failures = self._r.hincrby(self._key, "failures", 1)
            state = self._r.hget(self._key, "state") or "closed"
            if state == "half_open" or failures >= self.fail_threshold:
                self._r.hset(self._key, mapping={"state": "open", "opened_at": self._clock()})
            self._r.expire(self._key, self._ttl)
        except Exception as exc:  # noqa: BLE001
            _log.warning("redis breaker record_failure() failed for %s (%s); using in-process "
                        "fallback", self.name, exc)
            self._fallback.record_failure()

    @property
    def state(self) -> str:
        """Best-effort introspection (dashboards, tests) — never raises."""
        try:
            return self._r.hget(self._key, "state") or "closed"
        except Exception:  # noqa: BLE001
            return self._fallback.state


# --------------------------------------------------------------------------- #
# Alert dispatch throttle
# --------------------------------------------------------------------------- #

def redis_should_dispatch(client, key: str, window: int) -> bool | None:
    """True/False if Redis answered the throttle check; None if it errored
    (caller falls through to the in-process throttle on None, exactly like
    every other Redis path in this module degrading rather than raising).

    ``SET key 1 NX EX window`` is the whole implementation: atomically "claim
    this key for `window` seconds, but only if nobody already has" — exactly
    the dedup-gate semantics alerts_service._should_dispatch needs, with no
    read-modify-write race to reason about at all.
    """
    try:
        claimed = client.set(f"aops:throttle:{key}", "1", nx=True, ex=max(window, 1))
        return bool(claimed)
    except Exception as exc:  # noqa: BLE001
        _log.warning("redis alert throttle failed for %s (%s); using in-process fallback",
                    key, exc)
        return None


# --------------------------------------------------------------------------- #
# DLP custom-detector cache
# --------------------------------------------------------------------------- #

def redis_get_detectors(client, org_id: int | None) -> list[dict] | None:
    """Cached detector specs for org_id, or None on a miss/error (caller falls
    through to the DB query + in-process cache, same as any other miss)."""
    import json

    try:
        raw = client.get(f"aops:detectors:{org_id if org_id is not None else '_none'}")
        return json.loads(raw) if raw else None
    except Exception as exc:  # noqa: BLE001
        _log.warning("redis detector cache read failed for org %s (%s)", org_id, exc)
        return None


def redis_set_detectors(client, org_id: int | None, specs: list[dict], ttl: float) -> None:
    import json

    try:
        client.set(f"aops:detectors:{org_id if org_id is not None else '_none'}",
                  json.dumps(specs), ex=max(int(ttl), 1))
    except Exception as exc:  # noqa: BLE001 — best-effort; a DB read next call is fine
        _log.warning("redis detector cache write failed for org %s (%s)", org_id, exc)


def redis_invalidate_detectors(client, org_id: int | None) -> None:
    """Delete the shared cache entry so every worker sees the change on its
    very next request — this is the actual improvement over the in-process
    cache, which only ever invalidated the writer's own copy."""
    try:
        if org_id is None:
            keys = client.keys("aops:detectors:*")
            if keys:
                client.delete(*keys)
        else:
            client.delete(f"aops:detectors:{org_id}")
    except Exception as exc:  # noqa: BLE001 — worst case, the TTL catches up
        _log.warning("redis detector cache invalidate failed for org %s (%s)", org_id, exc)
