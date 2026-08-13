"""Tests for signed outbound webhooks.

post_json() enqueues for background delivery and returns immediately (see
webhooks.py for why: a slow — not even failed — receiver used to block every
authorize_action() in the product, since ledger.append() calls it inline).
Tests that need to observe what was actually POSTed call flush_pending_webhooks()
first to deterministically wait for the background dispatcher, rather than
racing an assertion against a background thread.
"""

import json
import time

import httpx

from agentguard.config import get_settings
from agentguard.webhooks import flush_pending_webhooks, post_json, sign_body, verify_signature


def test_sign_and_verify_roundtrip():
    body = b'{"a":1}'
    sig = sign_body(body, "secret")
    assert sig.startswith("sha256=")
    assert verify_signature(body, sig, "secret")
    assert not verify_signature(body, sig, "wrong-secret")
    assert not verify_signature(b'{"a":2}', sig, "secret")  # body tampered


def test_post_json_unsigned_when_no_secret(monkeypatch):
    captured = {}
    monkeypatch.setattr(get_settings(), "webhook_signing_secret", "")
    monkeypatch.setattr(httpx, "post", lambda url, **kw: captured.update(kw) or None)
    post_json("http://x/hook", {"k": "v"})
    assert flush_pending_webhooks()
    assert "X-AgentGuard-Signature" not in captured["headers"]
    assert json.loads(captured["content"]) == {"k": "v"}


def test_post_json_signed_when_secret_set(monkeypatch):
    captured = {}
    monkeypatch.setattr(get_settings(), "webhook_signing_secret", "s3cr3t")
    monkeypatch.setattr(httpx, "post", lambda url, **kw: captured.update(kw) or None)
    post_json("http://x/hook", {"k": "v"})
    assert flush_pending_webhooks()
    sig = captured["headers"]["X-AgentGuard-Signature"]
    assert verify_signature(captured["content"], sig, "s3cr3t")


def test_post_json_swallows_transport_errors(monkeypatch):
    def boom(url, **kw):
        raise httpx.ConnectError("down")
    monkeypatch.setattr(httpx, "post", boom)
    post_json("http://x/hook", {"k": "v"})  # must not raise
    assert flush_pending_webhooks()  # dispatcher itself must survive the error


def test_post_json_noop_on_empty_url(monkeypatch):
    called = []
    monkeypatch.setattr(httpx, "post", lambda url, **kw: called.append(url))
    post_json("", {"k": "v"})
    assert flush_pending_webhooks()
    assert called == []


def test_post_json_does_not_block_the_caller_on_a_slow_endpoint(monkeypatch):
    """Regression: a slow (not even failed) receiver used to block ledger.append()
    for the full request — and every authorize_action() calls it inline."""
    def slow_post(url, **kw):
        time.sleep(2.0)

    monkeypatch.setattr(httpx, "post", slow_post)
    started = time.perf_counter()
    post_json("http://x/hook", {"k": "v"})
    elapsed = time.perf_counter() - started
    assert elapsed < 0.5, f"post_json() blocked for {elapsed:.2f}s on a slow endpoint"
