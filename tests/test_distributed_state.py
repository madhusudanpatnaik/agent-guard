"""Tests for the Redis-backed circuit breaker / detector cache / alert throttle.

Mirrors test_counters.py's approach: a tiny in-memory FakeRedis stands in for
a real server (mimicking redis-py with decode_responses=True — strings in,
strings out, not bytes), so these run without any real Redis instance.
"""

from __future__ import annotations

import pytest

from agentguard import distributed_state
from agentguard.distributed_state import (
    RedisCircuitBreaker,
    redis_get_detectors,
    redis_invalidate_detectors,
    redis_set_detectors,
    redis_should_dispatch,
)
from agentguard.resilience import CircuitBreaker


class FakeRedis:
    """In-memory stand-in for the hash/string subset this module uses."""

    def __init__(self):
        self.hashes: dict[str, dict[str, str]] = {}
        self.strings: dict[str, str] = {}
        self.fail = False

    def _check(self):
        if self.fail:
            raise RuntimeError("boom")

    def hgetall(self, key):
        self._check()
        return dict(self.hashes.get(key, {}))

    def hget(self, key, field):
        self._check()
        return self.hashes.get(key, {}).get(field)

    def hset(self, key, field=None, value=None, mapping=None):
        self._check()
        h = self.hashes.setdefault(key, {})
        if mapping:
            for k, v in mapping.items():
                h[k] = str(v)
        else:
            h[field] = str(value)

    def hincrby(self, key, field, amount=1):
        self._check()
        h = self.hashes.setdefault(key, {})
        h[field] = str(int(h.get(field, 0)) + amount)
        return int(h[field])

    def expire(self, key, ttl):
        self._check()  # TTL bookkeeping not needed for these tests

    def set(self, key, value, nx=False, ex=None):
        self._check()
        if nx and key in self.strings:
            return None
        self.strings[key] = value
        return True

    def get(self, key):
        self._check()
        return self.strings.get(key)

    def delete(self, *keys):
        self._check()
        for k in keys:
            self.strings.pop(k, None)
            self.hashes.pop(k, None)

    def keys(self, pattern):
        self._check()
        prefix = pattern.rstrip("*")
        return [k for k in self.strings if k.startswith(prefix)]


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    yield
    # A few tests below monkeypatch get_client itself (to inject a shared fake
    # across multiple calls in one test) — pytest's own monkeypatch undo
    # restores the real, cache_clear-bearing function, but ordering relative
    # to this fixture's teardown isn't something to depend on either way.
    try:
        distributed_state.reset_distributed_state_cache()
    except AttributeError:
        pass


# --- get_client() resolution -------------------------------------------------

def test_get_client_defaults_to_none(monkeypatch):
    from agentguard.config import get_settings
    monkeypatch.setattr(get_settings(), "distributed_state_backend", "memory")
    distributed_state.reset_distributed_state_cache()
    assert distributed_state.get_client() is None


def test_get_client_none_when_redis_configured_without_url(monkeypatch):
    from agentguard.config import get_settings
    monkeypatch.setattr(get_settings(), "distributed_state_backend", "redis")
    monkeypatch.setattr(get_settings(), "redis_url", "")
    distributed_state.reset_distributed_state_cache()
    assert distributed_state.get_client() is None


# --- RedisCircuitBreaker -----------------------------------------------------

def test_breaker_opens_after_threshold():
    fake = FakeRedis()
    fallback = CircuitBreaker("svc")
    breaker = RedisCircuitBreaker(fake, "svc", fail_threshold=3, cooldown_seconds=30,
                                  fallback=fallback, wall_clock=lambda: 1000.0)
    assert breaker.allow() is True
    breaker.record_failure()
    breaker.record_failure()
    assert breaker.allow() is True  # still under threshold
    breaker.record_failure()  # 3rd failure -> open
    assert breaker.state == "open"
    assert breaker.allow() is False


def test_breaker_half_opens_after_cooldown_and_closes_on_success():
    fake = FakeRedis()
    now = [1000.0]
    breaker = RedisCircuitBreaker(fake, "svc", fail_threshold=1, cooldown_seconds=10,
                                  fallback=CircuitBreaker("svc"), wall_clock=lambda: now[0])
    breaker.record_failure()  # opens immediately (threshold=1)
    assert breaker.allow() is False

    now[0] += 11  # past cooldown
    assert breaker.allow() is True  # trial call granted -> half_open
    assert breaker.state == "half_open"

    breaker.record_success()
    assert breaker.state == "closed"
    assert breaker.allow() is True


def test_breaker_failed_trial_reopens_immediately():
    fake = FakeRedis()
    now = [1000.0]
    breaker = RedisCircuitBreaker(fake, "svc", fail_threshold=5, cooldown_seconds=10,
                                  fallback=CircuitBreaker("svc"), wall_clock=lambda: now[0])
    for _ in range(5):
        breaker.record_failure()
    assert breaker.state == "open"
    now[0] += 11
    assert breaker.allow() is True  # half_open trial
    breaker.record_failure()  # trial failed -> reopen, not "4/5 failures"
    assert breaker.state == "open"
    assert breaker.allow() is False


def test_breaker_falls_back_to_in_process_on_redis_error():
    fake = FakeRedis()
    fake.fail = True
    fallback = CircuitBreaker("svc", fail_threshold=1)
    breaker = RedisCircuitBreaker(fake, "svc", fail_threshold=1, cooldown_seconds=10,
                                  fallback=fallback)
    assert breaker.allow() is True  # falls back to fallback.allow()
    breaker.record_failure()  # falls back to fallback.record_failure()
    assert fallback.state == "open"
    assert breaker.allow() is False  # fallback now reports open too


def test_breaker_isolates_by_connector_name():
    fake = FakeRedis()
    a = RedisCircuitBreaker(fake, "svc-a", fail_threshold=1, cooldown_seconds=10,
                            fallback=CircuitBreaker("svc-a"))
    b = RedisCircuitBreaker(fake, "svc-b", fail_threshold=1, cooldown_seconds=10,
                            fallback=CircuitBreaker("svc-b"))
    a.record_failure()
    assert a.state == "open"
    assert b.state == "closed"
    assert b.allow() is True


# --- get_breaker() integration -----------------------------------------------

def test_get_breaker_returns_redis_backed_when_configured(monkeypatch):
    from agentguard.config import get_settings
    from agentguard import resilience

    monkeypatch.setattr(get_settings(), "distributed_state_backend", "redis")
    monkeypatch.setattr(get_settings(), "redis_url", "redis://fake/0")
    distributed_state.reset_distributed_state_cache()
    fake = FakeRedis()
    monkeypatch.setattr(distributed_state, "get_client", lambda: fake)
    resilience.reset_breakers()

    breaker = resilience.get_breaker("test-conn")
    assert isinstance(breaker, RedisCircuitBreaker)


def test_get_breaker_returns_in_process_by_default():
    from agentguard import resilience
    resilience.reset_breakers()
    breaker = resilience.get_breaker("test-conn-2")
    assert isinstance(breaker, CircuitBreaker)


# --- redis_should_dispatch ----------------------------------------------------

def test_should_dispatch_claims_once_then_throttles():
    fake = FakeRedis()
    assert redis_should_dispatch(fake, "org:kind:agent", 60) is True
    assert redis_should_dispatch(fake, "org:kind:agent", 60) is False


def test_should_dispatch_isolates_by_key():
    fake = FakeRedis()
    assert redis_should_dispatch(fake, "org:kind:1", 60) is True
    assert redis_should_dispatch(fake, "org:kind:2", 60) is True


def test_should_dispatch_returns_none_on_error():
    fake = FakeRedis()
    fake.fail = True
    assert redis_should_dispatch(fake, "org:kind:agent", 60) is None


def test_alerts_service_dedup_uses_redis_when_configured(monkeypatch):
    from agentguard.config import get_settings
    from agentguard import alerts_service
    from agentguard.models import Alert

    monkeypatch.setattr(get_settings(), "distributed_state_backend", "redis")
    monkeypatch.setattr(get_settings(), "redis_url", "redis://fake/0")
    distributed_state.reset_distributed_state_cache()
    fake = FakeRedis()
    monkeypatch.setattr(distributed_state, "get_client", lambda: fake)

    alert = Alert(org_id=1, kind="data_exfiltration", agent_id=7, severity="high",
                 title="t", detail="d")
    assert alerts_service._should_dispatch(alert, 60) is True
    assert alerts_service._should_dispatch(alert, 60) is False  # throttled via Redis


# --- detector cache -----------------------------------------------------------

def test_detector_cache_round_trip():
    fake = FakeRedis()
    assert redis_get_detectors(fake, 1) is None  # miss
    specs = [{"name": "custom", "pattern": "x", "severity": "high"}]
    redis_set_detectors(fake, 1, specs, ttl=30)
    assert redis_get_detectors(fake, 1) == specs


def test_detector_cache_invalidate_removes_entry():
    fake = FakeRedis()
    redis_set_detectors(fake, 1, [{"name": "a"}], ttl=30)
    redis_invalidate_detectors(fake, 1)
    assert redis_get_detectors(fake, 1) is None


def test_detector_cache_invalidate_all_orgs():
    fake = FakeRedis()
    redis_set_detectors(fake, 1, [{"name": "a"}], ttl=30)
    redis_set_detectors(fake, 2, [{"name": "b"}], ttl=30)
    redis_invalidate_detectors(fake, None)
    assert redis_get_detectors(fake, 1) is None
    assert redis_get_detectors(fake, 2) is None


def test_detector_cache_get_returns_none_on_error():
    fake = FakeRedis()
    fake.fail = True
    assert redis_get_detectors(fake, 1) is None


def test_gateway_service_uses_redis_detector_cache_immediately_across_workers(
    monkeypatch, db, admin_headers, client
):
    """The actual improvement over the in-process cache: invalidation is exact,
    not TTL-bounded, so a second 'worker' sees the change on its very next call
    rather than waiting up to _DETECTOR_TTL_SECONDS."""
    from agentguard.config import get_settings
    from agentguard import gateway_service

    monkeypatch.setattr(get_settings(), "distributed_state_backend", "redis")
    monkeypatch.setattr(get_settings(), "redis_url", "redis://fake/0")
    distributed_state.reset_distributed_state_cache()
    fake = FakeRedis()
    monkeypatch.setattr(distributed_state, "get_client", lambda: fake)

    org_id = 1
    specs = [{"name": "custom_secret", "pattern": "SECRET-\\d+", "severity": "high"}]
    fake.hashes.clear()  # n/a, just documenting intent
    redis_set_detectors(fake, org_id, specs, ttl=30)

    # A fresh call must see the shared cache entry immediately, simulating a
    # different worker process than whichever one loaded it from the DB.
    loaded = gateway_service._load_custom_detectors(db, org_id)
    assert loaded == specs

    gateway_service.invalidate_detector_cache(org_id)
    assert redis_get_detectors(fake, org_id) is None
