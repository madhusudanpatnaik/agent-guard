"""Tests for signed outbound webhooks."""

import json

import httpx

from agentops.config import get_settings
from agentops.webhooks import post_json, sign_body, verify_signature


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
    assert "X-AgentOps-Signature" not in captured["headers"]
    assert json.loads(captured["content"]) == {"k": "v"}


def test_post_json_signed_when_secret_set(monkeypatch):
    captured = {}
    monkeypatch.setattr(get_settings(), "webhook_signing_secret", "s3cr3t")
    monkeypatch.setattr(httpx, "post", lambda url, **kw: captured.update(kw) or None)
    post_json("http://x/hook", {"k": "v"})
    sig = captured["headers"]["X-AgentOps-Signature"]
    assert verify_signature(captured["content"], sig, "s3cr3t")


def test_post_json_swallows_transport_errors(monkeypatch):
    def boom(url, **kw):
        raise httpx.ConnectError("down")
    monkeypatch.setattr(httpx, "post", boom)
    post_json("http://x/hook", {"k": "v"})  # must not raise


def test_post_json_noop_on_empty_url(monkeypatch):
    called = []
    monkeypatch.setattr(httpx, "post", lambda url, **kw: called.append(url))
    post_json("", {"k": "v"})
    assert called == []
