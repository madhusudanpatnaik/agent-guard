"""Tests for agent reputation scoring + risk persistence on the ledger."""

from agentguard.audit.ledger import AuditLedger, verify_chain
from agentguard.models import Decision
from agentguard.reputation import compute


def _agent(db, name="RepBot"):
    from agentguard.models import Agent, Role
    role = Role(name=f"role-{name}")
    db.add(role)
    db.flush()
    a = Agent(name=name, role_id=role.id, api_key_hash=f"h-{name}", api_key_prefix="p")
    db.add(a)
    db.commit()
    db.refresh(a)
    return a


# --- risk persisted on the ledger (non-hashed) ------------------------------

def test_risk_persisted_but_not_in_hash(client, admin_headers):
    role = client.post("/api/roles", json={"name": "rp"}, headers=admin_headers).json()
    client.post(f"/api/roles/{role['id']}/policies", headers=admin_headers, json={
        "effect": "allow", "resource": "http:**", "actions": ["http.post"]})
    agent = client.post("/api/agents", json={"name": "RPBot", "role_id": role["id"]},
                        headers=admin_headers).json()
    r = client.post("/api/v1/gateway/authorize", headers={"X-API-Key": agent["api_key"]},
                    json={"action_type": "http.post", "resource": "http:novel/x",
                          "payload": {"note": "hi"}}).json()
    seq = r["audit_seq"]
    rec = client.get(f"/api/audit/records/{seq}", headers=admin_headers).json()
    assert rec["risk_score"] == r["risk_score"]
    assert rec["risk_score"] > 0            # novelty + egress scored
    assert rec["risk_factors"]              # factors recorded


def test_risk_columns_do_not_break_chain_integrity(db):
    led = AuditLedger(db)
    led.append(agent_id=1, agent_name="a", role_name="r", action_type="x", resource="y",
               decision=Decision.ALLOW, reason="", risk_score=88, risk_factors=["egress"])
    led.append(agent_id=1, agent_name="a", role_name="r", action_type="x", resource="z",
               decision=Decision.ALLOW, reason="", risk_score=10, risk_factors=[])
    status = verify_chain(db)
    assert status.valid is True   # risk is excluded from the hash pre-image


def test_tampering_risk_score_does_not_break_chain(db):
    # Risk is derived analytics, not a governance fact — editing it must NOT be
    # treated as ledger tampering (it isn't part of the hash commitment).
    from agentguard.models import AuditRecord
    led = AuditLedger(db)
    led.append(agent_id=1, agent_name="a", role_name="r", action_type="x", resource="y",
               decision=Decision.ALLOW, reason="", risk_score=10)
    rec = db.query(AuditRecord).filter(AuditRecord.seq == 0).one()
    rec.risk_score = 999
    db.commit()
    assert verify_chain(db).valid is True


# --- reputation -------------------------------------------------------------

def test_fresh_agent_is_trusted_but_unproven(db):
    a = _agent(db)
    rep = compute(db, a)
    assert rep.score == 100
    assert rep.band == "trusted"
    assert "no_history" in rep.factors
    assert rep.sample_size == 0


def test_clean_history_stays_trusted(db):
    a = _agent(db)
    led = AuditLedger(db)
    for i in range(5):
        led.append(agent_id=a.id, agent_name=a.name, role_name="r", action_type="read",
                   resource=f"db:{i}", decision=Decision.ALLOW, reason="", risk_score=5)
    rep = compute(db, a)
    assert rep.band == "trusted"
    assert rep.sample_size == 5


def test_high_denial_ratio_lowers_score(db):
    a = _agent(db)
    led = AuditLedger(db)
    for i in range(8):
        led.append(agent_id=a.id, agent_name=a.name, role_name="r", action_type="x",
                   resource="db:x", decision=Decision.DENY, reason="", risk_score=0)
    for i in range(2):
        led.append(agent_id=a.id, agent_name=a.name, role_name="r", action_type="x",
                   resource="db:x", decision=Decision.ALLOW, reason="", risk_score=0)
    rep = compute(db, a)
    assert rep.score < 70
    assert any("denial_ratio" in f for f in rep.factors)


def test_dlp_incidents_and_alerts_lower_score(db):
    from agentguard.models import Alert, AlertSeverity
    a = _agent(db)
    led = AuditLedger(db)
    for i in range(4):
        led.append(agent_id=a.id, agent_name=a.name, role_name="r", action_type="http.post",
                   resource="http:x", decision=Decision.DENY, reason="",
                   dlp_findings=[{"detector": "aws_access_key_id", "severity": "critical",
                                  "count": 1, "sample": "AKIA…", "path": "$"}],
                   risk_score=80)
    db.add(Alert(agent_id=a.id, kind="data_exfiltration", severity=AlertSeverity.HIGH,
                 title="x", org_id=a.org_id))
    db.commit()
    rep = compute(db, a)
    assert rep.band in ("risky", "untrusted")
    assert any("dlp_rate" in f for f in rep.factors)
    assert any("abuse_alerts" in f for f in rep.factors)


def test_reputation_endpoint(client, admin_headers):
    role = client.post("/api/roles", json={"name": "rep"}, headers=admin_headers).json()
    agent = client.post("/api/agents", json={"name": "EPBot", "role_id": role["id"]},
                        headers=admin_headers).json()
    r = client.get(f"/api/agents/{agent['id']}/reputation", headers=admin_headers)
    assert r.status_code == 200
    body = r.json()
    assert body["score"] == 100
    assert body["band"] == "trusted"
