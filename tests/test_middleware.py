"""Tests for security middleware: headers, body size limits, login rate limiting."""

from agentops.routers.auth import _login_failures


def test_security_headers_present_on_health(client):
    """Every response should carry the security headers."""
    resp = client.get("/health")
    assert resp.status_code == 200
    assert "DENY" in resp.headers.get("X-Frame-Options", "")
    assert "nosniff" in resp.headers.get("X-Content-Type-Options", "")
    assert "Content-Security-Policy" in resp.headers
    assert "Referrer-Policy" in resp.headers
    assert "Strict-Transport-Security" in resp.headers
    assert "Permissions-Policy" in resp.headers


def test_security_headers_on_api_response(client, admin_headers):
    """API responses also get security headers."""
    resp = client.get("/api/dashboard/stats", headers=admin_headers)
    assert resp.status_code == 200
    assert resp.headers.get("X-Frame-Options") == "DENY"


def test_ready_endpoint(client):
    """The /ready probe returns the database status."""
    resp = client.get("/ready")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ready"
    assert data["database"] == "ok"


def test_login_rate_limiter(client):
    """After repeated failures, login should return 429."""
    _login_failures.clear()  # ensure clean state
    for i in range(6):
        resp = client.post("/api/auth/login", json={"email": "bad@x.com", "password": "wrong"})
        if i < 5:
            assert resp.status_code == 401
        else:
            assert resp.status_code == 429
    _login_failures.clear()


def test_successful_login_resets_rate_limit(client):
    """A successful login should clear the failure counter."""
    _login_failures.clear()
    for _ in range(3):
        client.post("/api/auth/login", json={"email": "bad@x.com", "password": "wrong"})
    # Successful login
    resp = client.post("/api/auth/login", json={"email": "admin@agentops.local", "password": "admin"})
    assert resp.status_code == 200
    # Counter should be reset — 5 more failures should all be 401
    for i in range(5):
        resp = client.post("/api/auth/login", json={"email": "bad@x.com", "password": "wrong"})
        assert resp.status_code == 401
    _login_failures.clear()
