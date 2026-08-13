"""Pytest fixtures. Configures an isolated temp SQLite DB before importing the app."""

from __future__ import annotations

import os
import tempfile

# Must be set BEFORE importing any agentguard module (engine is built at import time).
_TMPDIR = tempfile.mkdtemp(prefix="agentguard-test-")
os.environ.setdefault("AGENTGUARD_DATABASE_URL", f"sqlite:///{_TMPDIR}/test.db")
os.environ.setdefault("AGENTGUARD_SECRET_KEY", "test-secret-key-only-for-tests-0000000000")
os.environ.setdefault("AGENTGUARD_BOOTSTRAP_ADMIN_PASSWORD", "admin")
# Disable the out-of-band anchor + SIEM by default so tests are isolated; the
# anchor truncation test opts back in with a temp path.
os.environ.setdefault("AGENTGUARD_AUDIT_ANCHOR_PATH", "")
os.environ.setdefault("AGENTGUARD_SIEM_WEBHOOK_URL", "")
os.environ.setdefault("AGENTGUARD_PROXY_CA_DIR", f"{_TMPDIR}/ca")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from agentguard.database import Base, SessionLocal, engine  # noqa: E402
from agentguard.main import app, bootstrap_admin  # noqa: E402


@pytest.fixture(autouse=True)
def fresh_db():
    from agentguard.audit.anchors import reset_anchor_cache
    from agentguard.audit.ledger import reset_chain_cache
    from agentguard.counters import reset_rate_backend_cache
    from agentguard.distributed_state import reset_distributed_state_cache
    from agentguard.gateway_service import invalidate_detector_cache

    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    bootstrap_admin()
    from agentguard.alerts_service import reset_alert_throttle
    from agentguard.resilience import reset_breakers

    # Drop process-global caches so one test's config never leaks into the next.
    reset_chain_cache()
    reset_anchor_cache()
    reset_rate_backend_cache()
    reset_distributed_state_cache()
    invalidate_detector_cache()  # per-org DLP detector cache must not leak
    reset_breakers()
    reset_alert_throttle()
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture
def admin_headers(client):
    resp = client.post(
        "/api/auth/login", json={"email": "admin@agentguard.local", "password": "admin"}
    )
    assert resp.status_code == 200, resp.text
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}
