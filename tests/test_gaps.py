"""Tests for the gap-analysis fixes: expiry, DLP bounding, anchoring, vault rotation."""

from datetime import datetime, timedelta, timezone

from agentguard.approvals_service import expire_if_stale, sweep_expired
from agentguard.audit.ledger import AuditLedger, verify_chain
from agentguard.config import get_settings
from agentguard.gateway_service import _recent_action_count, _scan_request_payload, authorize_action
from agentguard.models import Agent, Approval, ApprovalStatus, AuditRecord, Decision, Effect, Policy, Role
from agentguard.policy.engine import ActionRequest
from agentguard.vault import _fernet_for, reencrypt_secret


# --- vault key rotation -----------------------------------------------------

def test_reencrypt_vault_secret_roundtrip():
    old, new = "A" * 40, "B" * 40
    token = _fernet_for(old).encrypt(b"upstream-secret").decode()
    rotated = reencrypt_secret(token, old, new)
    assert rotated != token
    assert _fernet_for(new).decrypt(rotated.encode()).decode() == "upstream-secret"


# --- approval expiry --------------------------------------------------------

def _make_pending(db, *, expires_in: int) -> Approval:
    appr = Approval(
        agent_id=1, agent_name="a", action_type="payment.refund",
        resource="payment:stripe:refund", status=ApprovalStatus.PENDING,
        expires_at=datetime.now(timezone.utc) + timedelta(seconds=expires_in),
    )
    db.add(appr)
    db.commit()
    db.refresh(appr)
    return appr


def test_sweep_expired_flips_stale_pending(db):
    stale = _make_pending(db, expires_in=-10)
    fresh = _make_pending(db, expires_in=3600)
    assert sweep_expired(db) == 1
    db.refresh(stale)
    db.refresh(fresh)
    assert stale.status == ApprovalStatus.EXPIRED
    assert fresh.status == ApprovalStatus.PENDING


def test_expire_if_stale_is_noop_for_fresh(db):
    fresh = _make_pending(db, expires_in=3600)
    expire_if_stale(db, fresh)
    assert fresh.status == ApprovalStatus.PENDING


# --- request-payload DLP bounding ------------------------------------------

def test_oversized_request_payload_is_bounded_and_flagged(monkeypatch):
    monkeypatch.setattr(get_settings(), "max_request_scan_bytes", 200)
    huge = {"blob": "x" * 5000 + " AKIAIOSFODNN7EXAMPLE"}
    result = _scan_request_payload(huge)
    detectors = {f.detector for f in result.findings}
    assert "oversized_payload" in detectors  # truncation was flagged
    # And it did not raise / hang despite the large body.


def test_normal_payload_not_flagged_as_oversized(monkeypatch):
    monkeypatch.setattr(get_settings(), "max_request_scan_bytes", 256 * 1024)
    result = _scan_request_payload({"q": "select 1"})
    assert not any(f.detector == "oversized_payload" for f in result.findings)


# --- ledger head-truncation detection via the anchor -----------------------

def test_head_anchor_detects_truncation(db, tmp_path, monkeypatch):
    anchor = tmp_path / "anchor.log"
    monkeypatch.setattr(get_settings(), "audit_anchor_path", str(anchor))

    ledger = AuditLedger(db)
    for i in range(4):
        ledger.append(agent_id=1, agent_name="a", role_name="r",
                      action_type="db.read", resource=f"db:x:{i}",
                      decision=Decision.ALLOW, reason="ok")

    assert verify_chain(db).valid is True  # anchor head == db head

    # Attacker deletes the two newest rows directly in the DB.
    for rec in db.query(AuditRecord).order_by(AuditRecord.seq.desc()).limit(2):
        db.delete(rec)
    db.commit()

    status = verify_chain(db)
    assert status.valid is False
    assert "truncated" in status.detail


# --- billable accounting (quota / rate-limit correctness) -------------------

def test_derivative_rows_do_not_consume_rate_limit(db):
    role = Role(name="r")
    db.add(role)
    db.flush()
    db.add(Policy(role_id=role.id, effect=Effect.ALLOW, resource="x:*", actions=["act"],
                  conditions={"rate_limit": {"count": 2, "per_seconds": 3600}}))
    agent = Agent(name="a", role_id=role.id, api_key_hash="h", api_key_prefix="p", quota=1000)
    db.add(agent)
    db.commit()
    db.refresh(agent)

    req = ActionRequest("act", "x:1")

    d1 = authorize_action(db, agent, req).decision
    # Simulate the non-billable ".result" row an enforced execute would append.
    AuditLedger(db).append(agent_id=agent.id, agent_name="a", role_name="r",
                           action_type="act.result", resource="x:1",
                           decision=Decision.ALLOW, reason="", billable=False)
    assert _recent_action_count(db, agent.id, 3600) == 1  # result row excluded

    d2 = authorize_action(db, agent, req).decision
    assert _recent_action_count(db, agent.id, 3600) == 2
    d3 = authorize_action(db, agent, req).decision

    assert d1.decision == Decision.ALLOW
    assert d2.decision == Decision.ALLOW   # would wrongly DENY if result rows counted
    assert d3.decision == Decision.DENY    # rate limit hits at 2 billable actions


# --- audit head endpoint ----------------------------------------------------

def test_audit_head_endpoint(db, client, admin_headers):
    ledger = AuditLedger(db)
    for i in range(3):
        ledger.append(agent_id=1, agent_name="a", role_name="r",
                      action_type="db.read", resource=f"db:x:{i}",
                      decision=Decision.ALLOW, reason="ok")
    head = client.get("/api/audit/head", headers=admin_headers).json()
    assert head["count"] == 3
    assert head["seq"] == 2
    assert head["hash"]
