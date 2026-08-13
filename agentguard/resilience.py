"""Upstream resilience — bounded retries + a per-connector circuit breaker.

The plane makes the real call to the upstream on the agent's behalf. Two failure
modes matter: a *transient* blip (a dropped connection, a brief 5xx) that a
retry would ride through, and a *sustained* outage where retrying just piles
load onto a dead dependency and slows every agent behind it. This module
handles both:

* **Retries** — a small, bounded number of attempts with linear backoff on
  connection errors, timeouts, and 5xx responses (never on a 4xx, which is a
  real answer from the upstream).
* **Circuit breaker** — per connector/host. After N consecutive failed *calls*
  the circuit opens and further calls fail fast for a cooldown, instead of
  hanging; one trial call in HALF_OPEN closes it again on success.

Both the clock and sleep are injectable so the behavior is fully unit-testable
without real time.
"""

from __future__ import annotations

import threading
import time
from typing import Callable, Protocol

import httpx

from . import distributed_state
from .distributed_state import RedisCircuitBreaker


class _Breaker(Protocol):
    """Structural type satisfied by both CircuitBreaker and RedisCircuitBreaker
    — resilient_request() only needs these three methods, not which backs them."""

    name: str

    def allow(self) -> bool: ...
    def record_success(self) -> None: ...
    def record_failure(self) -> None: ...


class UpstreamUnavailable(Exception):
    """Raised when the circuit is open — the upstream is fast-failed."""


class CircuitState:
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreaker:
    def __init__(self, name: str, *, fail_threshold: int = 5,
                 cooldown_seconds: float = 30.0, clock: Callable[[], float] = time.monotonic):
        self.name = name
        self.fail_threshold = fail_threshold
        self.cooldown = cooldown_seconds
        self._clock = clock
        self._lock = threading.Lock()
        self._failures = 0
        self._opened_at: float | None = None
        self.state = CircuitState.CLOSED

    def allow(self) -> bool:
        """True if a call may proceed now (closed, or cooldown elapsed → trial)."""
        with self._lock:
            if self.state == CircuitState.OPEN:
                assert self._opened_at is not None
                if self._clock() - self._opened_at >= self.cooldown:
                    self.state = CircuitState.HALF_OPEN  # allow one trial call
                    return True
                return False
            return True

    def record_success(self) -> None:
        with self._lock:
            self._failures = 0
            self._opened_at = None
            self.state = CircuitState.CLOSED

    def record_failure(self) -> None:
        with self._lock:
            self._failures += 1
            # A failed trial in HALF_OPEN re-opens immediately; otherwise open
            # once the consecutive-failure threshold is crossed.
            if self.state == CircuitState.HALF_OPEN or self._failures >= self.fail_threshold:
                self.state = CircuitState.OPEN
                self._opened_at = self._clock()


_registry: dict[str, CircuitBreaker] = {}
_registry_lock = threading.Lock()


def get_breaker(name: str, *, fail_threshold: int = 5,
                cooldown_seconds: float = 30.0) -> _Breaker:
    """Return the breaker for ``name`` — Redis-backed when configured (see
    distributed_state.py), otherwise the in-process one. Same three-method
    interface either way, so resilient_request() and every caller don't need
    to know which. As with the pre-existing in-process registry, the first
    call for a given name wins its fail_threshold/cooldown_seconds; later
    calls with different values are silently ignored for that name — that
    was already true before this change, not introduced by it.
    """
    with _registry_lock:
        breaker = _registry.get(name)
        if breaker is None:
            breaker = CircuitBreaker(name, fail_threshold=fail_threshold,
                                     cooldown_seconds=cooldown_seconds)
            _registry[name] = breaker

    client = distributed_state.get_client()
    if client is None:
        return breaker
    return RedisCircuitBreaker(client, name, fail_threshold=fail_threshold,
                               cooldown_seconds=cooldown_seconds, fallback=breaker)


def reset_breakers() -> None:
    """Clear all breakers (tests)."""
    with _registry_lock:
        _registry.clear()


def resilient_request(
    breaker: _Breaker,
    do_request: Callable[[], httpx.Response],
    *,
    retries: int = 2,
    backoff: float = 0.2,
    sleep: Callable[[float], None] = time.sleep,
) -> httpx.Response:
    """Execute ``do_request`` with retries + the circuit breaker.

    Returns the response (including a final 5xx if all attempts 5xx). Raises
    :class:`UpstreamUnavailable` if the circuit is open, or the last
    ``httpx.HTTPError`` if every attempt raised. A call counts as one failure
    for the breaker only after all its retries are exhausted.
    """
    if not breaker.allow():
        raise UpstreamUnavailable(f"circuit open for '{breaker.name}' — upstream failing fast")

    last_exc: httpx.HTTPError | None = None
    last_resp: httpx.Response | None = None
    for attempt in range(retries + 1):
        try:
            resp = do_request()
        except httpx.HTTPError as exc:
            last_exc = exc
            last_resp = None
        else:
            if resp.status_code < 500:
                breaker.record_success()
                return resp
            last_resp = resp  # 5xx — retry, but remember it
        if attempt < retries:
            sleep(backoff * (attempt + 1))

    # All attempts failed (exception or 5xx) -> one failure for the breaker.
    breaker.record_failure()
    if last_resp is not None:
        return last_resp  # surface the upstream's own 5xx to the caller
    assert last_exc is not None
    raise last_exc
