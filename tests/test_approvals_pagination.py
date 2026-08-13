"""Pagination on the approvals list endpoint.

Every other list endpoint (agents, alerts, connectors, detectors, roles) caps
results at limit/offset with a 1,000-row ceiling; approvals was the one
exception with no bound at all, so an org that leans on approval-gated
policies would eventually load its entire approval history in one response.
"""

from __future__ import annotations

from datetime import datetime, timezone

from agentguard.database import SessionLocal
from agentguard.models import Approval, ApprovalStatus, User


def _agent_id(admin_headers, client) -> int:
    role = client.post("/api/roles", json={"name": "pager"}, headers=admin_headers).json()
    agent = client.post("/api/agents", json={"name": "PagerBot", "role_id": role["id"]},
                        headers=admin_headers).json()
    return agent["id"]


def _seed_approvals(agent_id: int, org_id: int, count: int) -> None:
    with SessionLocal() as db:
        for i in range(count):
            db.add(Approval(
                org_id=org_id, agent_id=agent_id, agent_name="PagerBot",
                action_type="pay.do", resource=f"pay:{i}",
                status=ApprovalStatus.PENDING, created_at=datetime.now(timezone.utc),
            ))
        db.commit()


def test_approvals_list_is_capped_and_pageable(client, admin_headers):
    agent_id = _agent_id(admin_headers, client)
    with SessionLocal() as db:
        org_id = db.query(User).filter(User.email == "admin@agentguard.local").one().org_id
    _seed_approvals(agent_id, org_id, 150)

    default_page = client.get("/api/approvals", headers=admin_headers).json()
    assert len(default_page) == 100, "default limit should cap at 100, matching every other list endpoint"

    capped = client.get("/api/approvals?limit=1000", headers=admin_headers).json()
    assert len(capped) == 150

    over_ceiling = client.get("/api/approvals?limit=5000", headers=admin_headers)
    assert over_ceiling.status_code == 422, "limit above 1000 must be rejected, not silently clamped"

    page1 = client.get("/api/approvals?limit=100&offset=0", headers=admin_headers).json()
    page2 = client.get("/api/approvals?limit=100&offset=100", headers=admin_headers).json()
    assert len(page1) == 100
    assert len(page2) == 50
    assert {a["id"] for a in page1}.isdisjoint({a["id"] for a in page2})
