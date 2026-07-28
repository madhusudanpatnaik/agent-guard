"""Tests for ABAC (attribute-based conditions) and the external policy engine."""

import httpx

from agentops.models import Decision, Effect, Policy
from agentops.policy.engine import ActionRequest, PolicyEngine
from agentops.policy.external import ExternalPolicyEngine


def _policy(pid, effect, resource, actions, **kw):
    return Policy(id=pid, role_id=1, name=kw.get("name", ""), effect=effect,
                  resource=resource, actions=actions, conditions=kw.get("conditions", {}),
                  require_approval=kw.get("require_approval", False),
                  priority=kw.get("priority", 0), enabled=True)


# --- ABAC -------------------------------------------------------------------

def test_abac_equality_gates_allow():
    eng = PolicyEngine()
    pol = _policy(1, Effect.ALLOW, "db:customers:*", ["read"],
                  conditions={"attributes": {"subject.clearance": {"op": "gte", "value": 3}}})
    high = ActionRequest("read", "db:customers:1", attributes={"subject": {"clearance": 5}})
    low = ActionRequest("read", "db:customers:1", attributes={"subject": {"clearance": 1}})
    assert eng.evaluate(high, [pol]).decision == Decision.ALLOW
    # Unsatisfied attribute -> policy doesn't apply -> default-deny.
    assert eng.evaluate(low, [pol]).decision == Decision.DENY


def test_abac_membership_and_glob():
    eng = PolicyEngine()
    pol = _policy(2, Effect.ALLOW, "http:**", ["http.get"],
                  conditions={"attributes": {
                      "env.region": ["us-east", "us-west"],
                      "resource.tier": {"op": "glob", "value": "gold*"},
                  }})
    ok = ActionRequest("http.get", "http:api/x",
                       attributes={"env": {"region": "us-west"}, "resource": {"tier": "gold-plus"}})
    bad_region = ActionRequest("http.get", "http:api/x",
                               attributes={"env": {"region": "eu"}, "resource": {"tier": "gold"}})
    assert eng.evaluate(ok, [pol]).decision == Decision.ALLOW
    assert eng.evaluate(bad_region, [pol]).decision == Decision.DENY


def test_abac_deny_policy_only_applies_when_attributes_match():
    eng = PolicyEngine()
    allow = _policy(1, Effect.ALLOW, "infra:*", ["ops.restart"], priority=1)
    # Deny only when NOT mfa-verified.
    deny = _policy(2, Effect.DENY, "infra:*", ["ops.restart"], priority=100,
                   conditions={"attributes": {"env.mfa": {"op": "eq", "value": False}}})
    no_mfa = ActionRequest("ops.restart", "infra:db", attributes={"env": {"mfa": False}})
    with_mfa = ActionRequest("ops.restart", "infra:db", attributes={"env": {"mfa": True}})
    assert eng.evaluate(no_mfa, [allow, deny]).decision == Decision.DENY
    assert eng.evaluate(with_mfa, [allow, deny]).decision == Decision.ALLOW


def test_abac_regex_operator():
    eng = PolicyEngine()
    pol = _policy(9, Effect.ALLOW, "db:*", ["read"],
                  conditions={"attributes": {"subject.ticket": {"op": "regex",
                                                                "value": r"^TCK-\d{4}$"}}})
    ok = ActionRequest("read", "db:x", attributes={"subject": {"ticket": "TCK-1234"}})
    bad = ActionRequest("read", "db:x", attributes={"subject": {"ticket": "nope"}})
    assert eng.evaluate(ok, [pol]).decision == Decision.ALLOW
    assert eng.evaluate(bad, [pol]).decision == Decision.DENY


def test_abac_malformed_regex_fails_closed():
    eng = PolicyEngine()
    pol = _policy(10, Effect.ALLOW, "db:*", ["read"],
                  conditions={"attributes": {"subject.x": {"op": "regex", "value": "([" }}})
    req = ActionRequest("read", "db:x", attributes={"subject": {"x": "anything"}})
    assert eng.evaluate(req, [pol]).decision == Decision.DENY  # bad pattern never matches


def test_abac_exists_operator():
    eng = PolicyEngine()
    pol = _policy(3, Effect.ALLOW, "db:*", ["read"],
                  conditions={"attributes": {"subject.ticket": {"op": "exists", "value": True}}})
    assert eng.evaluate(ActionRequest("read", "db:x",
                        attributes={"subject": {"ticket": "T-1"}}), [pol]).decision == Decision.ALLOW
    assert eng.evaluate(ActionRequest("read", "db:x",
                        attributes={"subject": {}}), [pol]).decision == Decision.DENY


def test_abac_subject_attributes_populated_end_to_end(client, admin_headers):
    """A policy keyed on the agent's own role name resolves via server-set attributes."""
    role = client.post("/api/roles", json={"name": "vip-support"}, headers=admin_headers).json()
    rid = role["id"]
    client.post(f"/api/roles/{rid}/policies", headers=admin_headers, json={
        "effect": "allow", "resource": "db:customers:*", "actions": ["read"],
        "conditions": {"attributes": {"subject.role": "vip-support"}}})
    agent = client.post("/api/agents", json={"name": "AbacBot", "role_id": rid},
                        headers=admin_headers).json()
    r = client.post("/api/v1/gateway/authorize", headers={"X-API-Key": agent["api_key"]},
                    json={"action_type": "read", "resource": "db:customers:1"}).json()
    assert r["decision"] == "allow"  # subject.role was injected server-side


# --- External policy engine (OPA / Cedar) -----------------------------------

def _engine(kind, handler, *, fail_open=False):
    client = httpx.Client(transport=httpx.MockTransport(handler))
    return ExternalPolicyEngine(kind=kind, url="http://policy.local/authz",
                                fail_open=fail_open, block_egress_on_secret=True, client=client)


def test_opa_boolean_result():
    eng = _engine("opa", lambda req: httpx.Response(200, json={"result": True}))
    d = eng.evaluate(ActionRequest("read", "db:x"))
    assert d.decision == Decision.ALLOW


def test_opa_object_result_require_approval():
    eng = _engine("opa", lambda req: httpx.Response(
        200, json={"result": {"allow": True, "require_approval": True, "reason": "big spend"}}))
    d = eng.evaluate(ActionRequest("payment.refund", "payment:x"))
    assert d.decision == Decision.REQUIRE_APPROVAL
    assert "big spend" in d.reason


def test_cedar_decision_mapping():
    allow = _engine("cedar", lambda req: httpx.Response(200, json={"decision": "Allow"}))
    deny = _engine("cedar", lambda req: httpx.Response(
        200, json={"decision": "Deny", "reasons": ["no matching permit"]}))
    assert allow.evaluate(ActionRequest("read", "db:x")).decision == Decision.ALLOW
    d = deny.evaluate(ActionRequest("read", "db:x"))
    assert d.decision == Decision.DENY
    assert "no matching permit" in d.reason


def test_external_engine_fails_closed_by_default():
    eng = _engine("opa", lambda req: httpx.Response(500, text="down"))
    d = eng.evaluate(ActionRequest("read", "db:x"))
    assert d.decision == Decision.DENY
    assert "fail-closed" in d.reason.lower()


def test_external_engine_fail_open_when_configured():
    eng = _engine("opa", lambda req: httpx.Response(500, text="down"), fail_open=True)
    d = eng.evaluate(ActionRequest("read", "db:x"))
    assert d.decision == Decision.ALLOW


def test_external_engine_still_blocks_dlp_exfiltration():
    from agentops.dlp.scanner import scan_payload
    # Even if OPA would allow, a secret on an egress action is blocked by AgentOps.
    eng = _engine("opa", lambda req: httpx.Response(200, json={"result": True}))
    dlp = scan_payload({"k": "AKIAIOSFODNN7EXAMPLE"})
    d = eng.evaluate(ActionRequest("http.post", "http:evil/exfil", payload={"k": "x"}), dlp=dlp)
    assert d.decision == Decision.DENY
    assert "exfiltration" in d.reason.lower()


def test_external_engine_receives_decision_input():
    captured = {}

    def handler(request: httpx.Request):
        import json
        captured.update(json.loads(request.content))
        return httpx.Response(200, json={"result": True})

    eng = _engine("opa", handler)
    req = ActionRequest("http.post", "http:api/x", metadata={"amount": 100},
                        attributes={"subject": {"role": "billing"}})
    eng.evaluate(req)
    assert captured["input"]["resource"] == "http:api/x"
    assert captured["input"]["attributes"]["subject"]["role"] == "billing"
    assert captured["input"]["is_egress"] is True
