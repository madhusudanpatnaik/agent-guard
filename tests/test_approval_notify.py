"""Tests for pending-approval notifications."""

import json

import httpx

from agentguard.config import get_settings


def _approval_agent(client, admin_headers):
    role = client.post("/api/roles", json={"name": "appr"}, headers=admin_headers).json()
    rid = role["id"]
    # Refunds above $500 require human approval.
    client.post(f"/api/roles/{rid}/policies", headers=admin_headers, json={
        "effect": "allow", "resource": "payment:stripe:refund",
        "actions": ["payment.refund"], "conditions": {"require_approval_over": 500}})
    agent = client.post("/api/agents", json={"name": "ApprBot", "role_id": rid},
                        headers=admin_headers).json()
    return {"X-API-Key": agent["api_key"]}


def _over_threshold(client, key):
    return client.post("/api/v1/gateway/authorize", headers=key, json={
        "action_type": "payment.refund", "resource": "payment:stripe:refund",
        "metadata": {"amount": 900}}).json()


def test_pending_approval_fires_notification(client, admin_headers, monkeypatch):
    captured = {}
    monkeypatch.setattr(get_settings(), "approval_webhook_url", "https://ops.example/approve")
    monkeypatch.setattr(httpx, "post", lambda url, **kw: captured.update({"url": url, **kw}) or None)
    key = _approval_agent(client, admin_headers)
    r = _over_threshold(client, key)
    assert r["decision"] == "require_approval"
    body = json.loads(captured["content"])
    assert captured["url"] == "https://ops.example/approve"
    assert body["event"] == "approval.pending"
    assert body["approval_id"] == r["approval_id"]
    assert body["resource"] == "payment:stripe:refund"


def test_notification_falls_back_to_alert_webhook(client, admin_headers, monkeypatch):
    calls = []
    monkeypatch.setattr(get_settings(), "approval_webhook_url", "")
    monkeypatch.setattr(get_settings(), "alert_webhook_url", "https://siem.example/hook")
    monkeypatch.setattr(httpx, "post", lambda url, **kw: calls.append(url) or None)
    key = _approval_agent(client, admin_headers)
    _over_threshold(client, key)
    assert "https://siem.example/hook" in calls


def test_no_notification_when_unconfigured(client, admin_headers, monkeypatch):
    calls = []
    monkeypatch.setattr(get_settings(), "approval_webhook_url", "")
    monkeypatch.setattr(get_settings(), "alert_webhook_url", "")
    monkeypatch.setattr(httpx, "post", lambda url, **kw: calls.append(url) or None)
    key = _approval_agent(client, admin_headers)
    r = _over_threshold(client, key)
    assert r["decision"] == "require_approval"   # still works
    assert calls == []                            # but no webhook attempted


def test_notification_is_slack_formatted_for_slack_url(client, admin_headers, monkeypatch):
    captured = {}
    monkeypatch.setattr(get_settings(), "approval_webhook_url",
                        "https://hooks.slack.com/services/T/B/X")
    monkeypatch.setattr(httpx, "post", lambda url, **kw: captured.update(kw) or None)
    key = _approval_agent(client, admin_headers)
    _over_threshold(client, key)
    assert "text" in json.loads(captured["content"])   # Slack-shaped


def test_allowed_action_sends_no_approval_notification(client, admin_headers, monkeypatch):
    calls = []
    monkeypatch.setattr(get_settings(), "approval_webhook_url", "https://ops.example/approve")
    monkeypatch.setattr(httpx, "post", lambda url, **kw: calls.append(url) or None)
    key = _approval_agent(client, admin_headers)
    # Under threshold -> allowed, no approval -> no notification.
    r = client.post("/api/v1/gateway/authorize", headers=key, json={
        "action_type": "payment.refund", "resource": "payment:stripe:refund",
        "metadata": {"amount": 100}}).json()
    assert r["decision"] == "allow"
    assert calls == []
