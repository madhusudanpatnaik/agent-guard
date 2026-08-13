"""Tests for background tasks and Prometheus metrics."""

from datetime import datetime, timedelta, timezone

from agentguard.approvals_service import sweep_expired
from agentguard.models import Approval, ApprovalStatus


def test_sweep_expired_transitions_stale(db):
    """Proactive sweeper transitions stale pending approvals."""
    stale = Approval(
        agent_id=1, agent_name="a", action_type="act", resource="r",
        status=ApprovalStatus.PENDING,
        expires_at=datetime.now(timezone.utc) - timedelta(seconds=60),
    )
    fresh = Approval(
        agent_id=1, agent_name="b", action_type="act", resource="r",
        status=ApprovalStatus.PENDING,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    already = Approval(
        agent_id=1, agent_name="c", action_type="act", resource="r",
        status=ApprovalStatus.APPROVED,
    )
    db.add_all([stale, fresh, already])
    db.commit()
    count = sweep_expired(db)
    assert count == 1
    db.refresh(stale)
    db.refresh(fresh)
    db.refresh(already)
    assert stale.status == ApprovalStatus.EXPIRED
    assert fresh.status == ApprovalStatus.PENDING
    assert already.status == ApprovalStatus.APPROVED


def test_prometheus_metrics_endpoint(client, admin_headers, db):
    """The /api/dashboard/metrics endpoint returns Prometheus text format."""
    resp = client.get("/api/dashboard/metrics", headers=admin_headers)
    assert resp.status_code == 200
    text = resp.text
    assert "agentguard_agents_total" in text
    assert "agentguard_decisions_total" in text
    assert "agentguard_ledger_valid" in text
    assert "agentguard_connectors_total" in text


def test_dashboard_stats_include_connectors(client, admin_headers):
    """DashboardStats now includes connector counts."""
    resp = client.get("/api/dashboard/stats", headers=admin_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "connectors_total" in data
    assert "connectors_active" in data
