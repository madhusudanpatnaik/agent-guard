"""Tests for governance-ops features: policy simulator (dry-run) + audit export."""

import csv
import io
import json


# --------------------------------------------------------------------------- #
# Policy simulator
# --------------------------------------------------------------------------- #

def _role_with_policy(client, admin_headers, effect, resource, actions, **cond):
    role = client.post("/api/roles", json={"name": "sim-role"}, headers=admin_headers).json()
    body = {"effect": effect, "resource": resource, "actions": actions}
    if cond:
        body["conditions"] = cond
    client.post(f"/api/roles/{role['id']}/policies", json=body, headers=admin_headers)
    return role["id"]


def _simulate(client, admin_headers, **body):
    return client.post("/api/policy/simulate", json=body, headers=admin_headers)


def test_simulate_allow_against_role(client, admin_headers):
    rid = _role_with_policy(client, admin_headers, "allow", "db:analytics:*", ["db.read"])
    r = _simulate(client, admin_headers, role_id=rid,
                  action_type="db.read", resource="db:analytics:events").json()
    assert r["decision"] == "allow"
    assert r["evaluated_policies"] == 1


def test_simulate_default_deny(client, admin_headers):
    rid = _role_with_policy(client, admin_headers, "allow", "db:x:*", ["db.read"])
    r = _simulate(client, admin_headers, role_id=rid,
                  action_type="db.write", resource="db:secrets:root").json()
    assert r["decision"] == "deny"


def test_simulate_adhoc_policies_saves_nothing(client, admin_headers):
    before = client.get("/api/roles", headers=admin_headers).json()
    r = _simulate(
        client, admin_headers,
        action_type="payment.refund", resource="payment:stripe:refund",
        metadata={"amount": 900},
        policies=[{
            "effect": "allow", "resource": "payment:stripe:refund",
            "actions": ["payment.refund"], "conditions": {"require_approval_over": 500},
        }],
    ).json()
    assert r["decision"] == "require_approval"      # 900 > 500 threshold
    after = client.get("/api/roles", headers=admin_headers).json()
    assert len(after) == len(before)                # nothing persisted


def test_simulate_dlp_egress_block(client, admin_headers):
    r = _simulate(
        client, admin_headers,
        action_type="http.post", resource="http:evil.example/exfil",
        payload={"leak": "AKIAIOSFODNN7EXAMPLE"},
        policies=[{"effect": "allow", "resource": "http:**", "actions": ["http.post"]}],
    ).json()
    assert r["decision"] == "deny"
    assert r["is_egress"] is True
    assert any(f["detector"] == "aws_access_key_id" for f in r["dlp_findings"])


def test_simulate_requires_a_target(client, admin_headers):
    r = _simulate(client, admin_headers, action_type="db.read", resource="db:x")
    assert r.status_code == 400


def test_simulate_writes_nothing_to_ledger(client, admin_headers):
    rid = _role_with_policy(client, admin_headers, "allow", "db:x:*", ["db.read"])
    before = client.get("/api/audit/verify", headers=admin_headers).json()["length"]
    _simulate(client, admin_headers, role_id=rid, action_type="db.read", resource="db:x:1")
    after = client.get("/api/audit/verify", headers=admin_headers).json()["length"]
    assert after == before  # dry-run never touches the ledger


def test_simulate_requires_admin(client):
    r = client.post("/api/policy/simulate",
                    json={"action_type": "db.read", "resource": "db:x", "role_id": 1})
    assert r.status_code == 401


# --------------------------------------------------------------------------- #
# Audit export
# --------------------------------------------------------------------------- #

def _seed_records(db):
    from sqlalchemy import select

    from agentops.audit.ledger import AuditLedger
    from agentops.models import Decision, User
    oid = db.scalar(select(User).where(User.email == "admin@agentops.local")).org_id
    ledger = AuditLedger(db)
    ledger.append(agent_id=None, agent_name="a", role_name="r", action_type="db.read",
                  resource="db:x", decision=Decision.ALLOW, reason="ok", org_id=oid)
    ledger.append(agent_id=None, agent_name="a", role_name="r", action_type="http.post",
                  resource="http:y", decision=Decision.DENY, reason="blocked", org_id=oid)


def test_export_csv(client, admin_headers, db):
    _seed_records(db)
    resp = client.get("/api/audit/export?fmt=csv", headers=admin_headers)
    assert resp.status_code == 200
    assert "text/csv" in resp.headers["content-type"]
    rows = list(csv.DictReader(io.StringIO(resp.text)))
    assert len(rows) == 2
    assert {r["decision"] for r in rows} == {"allow", "deny"}
    assert "hash" in rows[0]


def test_export_jsonl(client, admin_headers, db):
    _seed_records(db)
    resp = client.get("/api/audit/export?fmt=jsonl", headers=admin_headers)
    assert resp.status_code == 200
    lines = [json.loads(x) for x in resp.text.splitlines() if x.strip()]
    assert len(lines) == 2
    assert all("action_type" in obj for obj in lines)


def test_export_decision_filter(client, admin_headers, db):
    _seed_records(db)
    resp = client.get("/api/audit/export?fmt=jsonl&decision=deny", headers=admin_headers)
    lines = [json.loads(x) for x in resp.text.splitlines() if x.strip()]
    assert len(lines) == 1
    assert lines[0]["decision"] == "deny"
