"""Tests for detect & respond — risk alerts + webhook notifications."""

import httpx

from agentops.config import get_settings


def _agent(client, admin_headers, *, resource=None, actions=None):
    role = client.post("/api/roles", json={"name": "alerted"}, headers=admin_headers).json()
    if resource:
        client.post(f"/api/roles/{role['id']}/policies", headers=admin_headers,
                    json={"effect": "allow", "resource": resource, "actions": actions})
    a = client.post("/api/agents", json={"name": "AlertBot", "role_id": role["id"]},
                    headers=admin_headers).json()
    return {"X-API-Key": a["api_key"]}


def _authorize(client, key, action_type, resource, **body):
    return client.post("/api/v1/gateway/authorize", headers=key,
                       json={"action_type": action_type, "resource": resource, **body})


def test_dlp_exfiltration_raises_high_alert(client, admin_headers):
    key = _agent(client, admin_headers, resource="http:evil.example/**", actions=["http.post"])
    r = _authorize(client, key, "http.post", "http:evil.example/x",
                   payload={"leak": "AKIAIOSFODNN7EXAMPLE"}).json()
    assert r["decision"] == "deny"
    alerts = client.get("/api/alerts", headers=admin_headers).json()
    assert any(a["kind"] == "data_exfiltration" and a["severity"] == "high" for a in alerts)


def test_denial_spike_raises_anomaly_alert(client, admin_headers, monkeypatch):
    monkeypatch.setattr(get_settings(), "alert_denial_spike_count", 3)
    key = _agent(client, admin_headers)  # no policy -> everything denied
    for _ in range(3):
        _authorize(client, key, "do", "thing:1")
    alerts = client.get("/api/alerts?severity=medium", headers=admin_headers).json()
    assert any(a["kind"] == "denial_spike" for a in alerts)


def test_alert_dashboard_count(client, admin_headers):
    key = _agent(client, admin_headers, resource="http:x/**", actions=["http.post"])
    _authorize(client, key, "http.post", "http:x/y", payload={"k": "AKIAIOSFODNN7EXAMPLE"})
    stats = client.get("/api/dashboard/stats", headers=admin_headers).json()
    assert stats["alerts_open"] >= 1


def test_acknowledge_alert(client, admin_headers):
    key = _agent(client, admin_headers, resource="http:x/**", actions=["http.post"])
    _authorize(client, key, "http.post", "http:x/y", payload={"k": "AKIAIOSFODNN7EXAMPLE"})
    alert = client.get("/api/alerts", headers=admin_headers).json()[0]
    r = client.post(f"/api/alerts/{alert['id']}/ack", headers=admin_headers).json()
    assert r["status"] == "acknowledged"
    assert r["acknowledged_by"] == "admin@agentops.local"


def test_webhook_is_dispatched_for_high_alert(client, admin_headers, monkeypatch):
    calls = []
    monkeypatch.setattr(get_settings(), "alert_webhook_url", "https://siem.example/hook")
    monkeypatch.setattr(httpx, "post", lambda url, **kw: calls.append((url, kw)) or None)
    key = _agent(client, admin_headers, resource="http:x/**", actions=["http.post"])
    _authorize(client, key, "http.post", "http:x/y", payload={"k": "AKIAIOSFODNN7EXAMPLE"})
    assert calls, "expected a webhook POST for the high-severity alert"
    assert calls[0][0] == "https://siem.example/hook"


def test_webhook_is_hmac_signed_when_secret_set(client, admin_headers, monkeypatch):
    import json as _json

    from agentops.webhooks import verify_signature
    captured = {}
    monkeypatch.setattr(get_settings(), "alert_webhook_url", "https://siem.example/hook")
    monkeypatch.setattr(get_settings(), "webhook_signing_secret", "top-secret")
    monkeypatch.setattr(httpx, "post", lambda url, **kw: captured.update(kw) or None)
    key = _agent(client, admin_headers, resource="http:x/**", actions=["http.post"])
    _authorize(client, key, "http.post", "http:x/y", payload={"k": "AKIAIOSFODNN7EXAMPLE"})
    body = captured["content"]
    sig = captured["headers"]["X-AgentOps-Signature"]
    # The signature verifies over the EXACT bytes posted, and the body is real JSON.
    assert verify_signature(body, sig, "top-secret")
    assert _json.loads(body)["kind"] == "data_exfiltration"


def test_auto_containment_suspends_agent(client, admin_headers, monkeypatch):
    monkeypatch.setattr(get_settings(), "auto_suspend_on_exfil_attempts", 2)
    key = _agent(client, admin_headers, resource="http:evil/**", actions=["http.post"])
    for _ in range(2):
        _authorize(client, key, "http.post", "http:evil/x",
                   payload={"k": "AKIAIOSFODNN7EXAMPLE"})
    # The agent is now suspended — its next request is rejected at auth.
    r = _authorize(client, key, "http.post", "http:evil/x", payload={"k": "x"})
    assert r.status_code == 403
    criticals = client.get("/api/alerts?severity=critical", headers=admin_headers).json()
    assert any(a["kind"] == "auto_suspend" for a in criticals)


def test_slack_format_for_slack_url(client, admin_headers, monkeypatch):
    import json as _json
    captured = {}
    monkeypatch.setattr(get_settings(), "alert_webhook_url",
                        "https://hooks.slack.com/services/T/B/X")
    monkeypatch.setattr(httpx, "post", lambda url, **kw: captured.update(kw) or None)
    key = _agent(client, admin_headers, resource="http:x/**", actions=["http.post"])
    _authorize(client, key, "http.post", "http:x/y", payload={"k": "AKIAIOSFODNN7EXAMPLE"})
    assert "text" in _json.loads(captured["content"])   # Slack-shaped payload


# --- webhook dedup / rate-limiting -----------------------------------------

def test_repeat_alerts_dedup_the_webhook(client, admin_headers, monkeypatch):
    calls = []
    monkeypatch.setattr(get_settings(), "alert_webhook_url", "https://siem.example/hook")
    monkeypatch.setattr(get_settings(), "alert_webhook_dedup_window", 60)
    monkeypatch.setattr(httpx, "post", lambda url, **kw: calls.append(url) or None)
    key = _agent(client, admin_headers, resource="http:x/**", actions=["http.post"])
    # Two identical exfiltration attempts from the same agent in the window.
    _authorize(client, key, "http.post", "http:x/y", payload={"k": "AKIAIOSFODNN7EXAMPLE"})
    _authorize(client, key, "http.post", "http:x/z", payload={"k": "AKIAIOSFODNN7EXAMPLE"})
    # Both alerts recorded, but only ONE webhook fired.
    alerts = client.get("/api/alerts", headers=admin_headers).json()
    assert sum(1 for a in alerts if a["kind"] == "data_exfiltration") >= 2
    assert len(calls) == 1


def test_dedup_window_zero_disables_throttle(client, admin_headers, monkeypatch):
    calls = []
    monkeypatch.setattr(get_settings(), "alert_webhook_url", "https://siem.example/hook")
    monkeypatch.setattr(get_settings(), "alert_webhook_dedup_window", 0)
    monkeypatch.setattr(httpx, "post", lambda url, **kw: calls.append(url) or None)
    key = _agent(client, admin_headers, resource="http:x/**", actions=["http.post"])
    _authorize(client, key, "http.post", "http:x/y", payload={"k": "AKIAIOSFODNN7EXAMPLE"})
    _authorize(client, key, "http.post", "http:x/z", payload={"k": "AKIAIOSFODNN7EXAMPLE"})
    assert len(calls) == 2  # no dedup -> both dispatched
