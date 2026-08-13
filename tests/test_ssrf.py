"""Tests for the SSRF egress guard on connector HTTP calls."""

import pytest

from agentguard.config import get_settings
from agentguard.egress import _host_is_internal, check_egress


@pytest.mark.parametrize("host,blocked", [
    ("127.0.0.1", True),
    ("10.0.0.1", True),
    ("192.168.1.5", True),
    ("172.16.0.9", True),
    ("169.254.169.254", True),   # cloud metadata
    ("::1", True),
    ("0.0.0.0", True),
    ("metadata.google.internal", True),
    ("8.8.8.8", False),          # public
    ("1.1.1.1", False),
])
def test_host_internal_classification(host, blocked):
    assert _host_is_internal(host) is blocked


def test_check_egress_is_noop_when_disabled(monkeypatch):
    monkeypatch.setattr(get_settings(), "block_private_egress", False)
    check_egress("http://127.0.0.1:9100/x")  # must not raise


def test_check_egress_blocks_metadata_when_enabled(monkeypatch):
    monkeypatch.setattr(get_settings(), "block_private_egress", True)
    with pytest.raises(ValueError):
        check_egress("http://169.254.169.254/latest/meta-data/")


def test_execute_to_private_connector_is_blocked(client, admin_headers, monkeypatch):
    monkeypatch.setattr(get_settings(), "block_private_egress", True)
    client.post("/api/connectors", headers=admin_headers, json={
        "name": "internal", "base_url": "http://127.0.0.1:9100", "auth_type": "none"})
    role = client.post("/api/roles", headers=admin_headers, json={"name": "r"}).json()
    client.post(f"/api/roles/{role['id']}/policies", headers=admin_headers, json={
        "effect": "allow", "resource": "http:internal/**", "actions": ["http.get"]})
    agent = client.post("/api/agents", headers=admin_headers,
                        json={"name": "A", "role_id": role["id"]}).json()
    r = client.post("/api/v1/gateway/execute", headers={"X-API-Key": agent["api_key"]},
                    json={"connector": "internal", "method": "GET", "path": "/x"})
    assert r.status_code == 400
    assert "blocked" in r.json()["detail"]


def test_connector_test_blocks_private_target(client, admin_headers, monkeypatch):
    monkeypatch.setattr(get_settings(), "block_private_egress", True)
    c = client.post("/api/connectors", headers=admin_headers, json={
        "name": "internal2", "base_url": "http://10.0.0.5", "auth_type": "none"}).json()
    r = client.post(f"/api/connectors/{c['id']}/test", headers=admin_headers).json()
    assert r["reachable"] is False
    assert "blocked" in (r["error"] or "")
