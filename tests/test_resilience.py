"""Tests for upstream retries + the circuit breaker."""

import httpx
import pytest

from agentguard.resilience import (
    CircuitBreaker,
    CircuitState,
    UpstreamUnavailable,
    resilient_request,
)


class FakeClock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt


def _resp(code):
    return httpx.Response(code, request=httpx.Request("GET", "http://x"))


# --- retries ----------------------------------------------------------------

def test_succeeds_first_try_no_retry():
    calls = []
    br = CircuitBreaker("c")
    r = resilient_request(br, lambda: calls.append(1) or _resp(200),
                          retries=2, sleep=lambda s: None)
    assert r.status_code == 200
    assert len(calls) == 1
    assert br.state == CircuitState.CLOSED


def test_retries_on_transient_error_then_succeeds():
    seq = [httpx.ConnectError("boom"), httpx.ConnectError("boom"), _resp(200)]

    def do():
        x = seq.pop(0)
        if isinstance(x, Exception):
            raise x
        return x

    br = CircuitBreaker("c")
    r = resilient_request(br, do, retries=2, sleep=lambda s: None)
    assert r.status_code == 200
    assert br.state == CircuitState.CLOSED  # recovered within retries


def test_retries_on_5xx_then_surfaces_final_5xx():
    br = CircuitBreaker("c")
    r = resilient_request(br, lambda: _resp(503), retries=2, sleep=lambda s: None)
    assert r.status_code == 503          # returns the upstream's own 5xx
    # A fully-failed call counts as one breaker failure.
    assert br._failures == 1


def test_does_not_retry_on_4xx():
    calls = []
    br = CircuitBreaker("c")
    r = resilient_request(br, lambda: calls.append(1) or _resp(404),
                          retries=3, sleep=lambda s: None)
    assert r.status_code == 404
    assert len(calls) == 1               # 4xx is a real answer, not retried
    assert br.state == CircuitState.CLOSED


def test_all_attempts_raise_reraises_last():
    br = CircuitBreaker("c")
    with pytest.raises(httpx.ConnectError):
        resilient_request(br, lambda: (_ for _ in ()).throw(httpx.ConnectError("down")),
                          retries=1, sleep=lambda s: None)
    assert br._failures == 1


# --- circuit breaker --------------------------------------------------------

def test_circuit_opens_after_threshold_then_fast_fails():
    clock = FakeClock()
    br = CircuitBreaker("c", fail_threshold=3, cooldown_seconds=30, clock=clock)
    for _ in range(3):
        resilient_request(br, lambda: _resp(500), retries=0, sleep=lambda s: None)
    assert br.state == CircuitState.OPEN
    # Now calls fast-fail without invoking do_request.
    called = []
    with pytest.raises(UpstreamUnavailable):
        resilient_request(br, lambda: called.append(1) or _resp(200),
                          retries=0, sleep=lambda s: None)
    assert called == []


def test_circuit_half_opens_after_cooldown_and_closes_on_success():
    clock = FakeClock()
    br = CircuitBreaker("c", fail_threshold=2, cooldown_seconds=30, clock=clock)
    for _ in range(2):
        resilient_request(br, lambda: _resp(500), retries=0, sleep=lambda s: None)
    assert br.state == CircuitState.OPEN

    clock.advance(31)  # cooldown elapses -> one trial call allowed
    r = resilient_request(br, lambda: _resp(200), retries=0, sleep=lambda s: None)
    assert r.status_code == 200
    assert br.state == CircuitState.CLOSED   # trial succeeded -> closed


def test_circuit_reopens_if_trial_fails():
    clock = FakeClock()
    br = CircuitBreaker("c", fail_threshold=2, cooldown_seconds=30, clock=clock)
    for _ in range(2):
        resilient_request(br, lambda: _resp(500), retries=0, sleep=lambda s: None)
    clock.advance(31)
    # Trial call fails -> immediately re-opens.
    resilient_request(br, lambda: _resp(500), retries=0, sleep=lambda s: None)
    assert br.state == CircuitState.OPEN


def test_success_resets_failure_count():
    br = CircuitBreaker("c", fail_threshold=3)
    resilient_request(br, lambda: _resp(500), retries=0, sleep=lambda s: None)
    resilient_request(br, lambda: _resp(200), retries=0, sleep=lambda s: None)
    assert br._failures == 0


# --- end-to-end through enforced execution ---------------------------------

def test_enforced_execution_retries_transient_failure(client, admin_headers, monkeypatch):
    from agentguard import gateway_service
    from agentguard.config import get_settings

    monkeypatch.setattr(get_settings(), "upstream_retry_backoff", 0.0)  # no real sleep
    attempts = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        attempts["n"] += 1
        if attempts["n"] == 1:
            raise httpx.ConnectError("transient")  # first attempt fails
        return httpx.Response(200, json={"ok": True})

    real_client = httpx.Client

    def factory(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(*args, **kwargs)

    monkeypatch.setattr(gateway_service.httpx, "Client", factory)

    client.post("/api/connectors", headers=admin_headers, json={
        "name": "flaky", "base_url": "http://up.local", "auth_type": "none"})
    role = client.post("/api/roles", headers=admin_headers, json={"name": "ro"}).json()
    client.post(f"/api/roles/{role['id']}/policies", headers=admin_headers, json={
        "effect": "allow", "resource": "http:flaky/**", "actions": ["http.get"]})
    agent = client.post("/api/agents", headers=admin_headers,
                        json={"name": "FlakyBot", "role_id": role["id"]}).json()

    r = client.post("/api/v1/gateway/execute", headers={"X-API-Key": agent["api_key"]},
                    json={"connector": "flaky", "method": "GET", "path": "/data"}).json()
    assert r["executed"] is True          # succeeded on retry
    assert r["status_code"] == 200
    assert attempts["n"] == 2             # one failure + one success
