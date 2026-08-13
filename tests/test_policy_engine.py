"""Unit tests for the policy decision point and glob matcher."""

from datetime import datetime, timezone

from agentguard.models import Decision, Effect, Policy
from agentguard.policy.engine import ActionRequest, PolicyEngine, glob_match


def _policy(pid, effect, resource, actions, **kw):
    return Policy(
        id=pid,
        role_id=1,
        name=kw.get("name", ""),
        effect=effect,
        resource=resource,
        actions=actions,
        conditions=kw.get("conditions", {}),
        require_approval=kw.get("require_approval", False),
        priority=kw.get("priority", 0),
        enabled=kw.get("enabled", True),
    )


def test_glob_matching():
    assert glob_match("db:customers:*", "db:customers:1042")
    assert not glob_match("db:customers:*", "db:orders:1042")
    assert glob_match("http:**", "http:api.stripe.com/v1/charges")
    assert not glob_match("db:customers:*", "db:customers:sub:1")  # * stays in segment
    assert glob_match("db:customers:**", "db:customers:sub:1")


def test_default_deny_when_no_policy():
    eng = PolicyEngine(default_deny=True)
    d = eng.evaluate(ActionRequest("db.read", "db:customers:1"), [])
    assert d.decision == Decision.DENY
    assert "Default-deny" in d.reason


def test_allow_when_matching_policy():
    eng = PolicyEngine()
    pol = _policy(7, Effect.ALLOW, "db:customers:*", ["read"])
    d = eng.evaluate(ActionRequest("read", "db:customers:1"), [pol])
    assert d.decision == Decision.ALLOW
    assert d.matched_policy_id == 7


def test_deny_overrides_allow():
    eng = PolicyEngine()
    allow = _policy(1, Effect.ALLOW, "db:customers:*", ["*"], priority=1)
    deny = _policy(2, Effect.DENY, "db:customers:*", ["write"], priority=100)
    d = eng.evaluate(ActionRequest("write", "db:customers:1"), [allow, deny])
    assert d.decision == Decision.DENY
    assert d.matched_policy_id == 2


def test_require_approval_flag():
    eng = PolicyEngine()
    pol = _policy(3, Effect.ALLOW, "payment:**", ["payment.refund"], require_approval=True)
    d = eng.evaluate(ActionRequest("payment.refund", "payment:stripe:refund"), [pol])
    assert d.decision == Decision.REQUIRE_APPROVAL


def test_amount_threshold_requires_approval():
    eng = PolicyEngine()
    pol = _policy(4, Effect.ALLOW, "payment:**", ["payment.refund"],
                  conditions={"require_approval_over": 500})
    over = eng.evaluate(
        ActionRequest("payment.refund", "payment:stripe:refund", metadata={"amount": 900}), [pol]
    )
    under = eng.evaluate(
        ActionRequest("payment.refund", "payment:stripe:refund", metadata={"amount": 100}), [pol]
    )
    assert over.decision == Decision.REQUIRE_APPROVAL
    assert under.decision == Decision.ALLOW


def test_max_amount_denies():
    eng = PolicyEngine()
    pol = _policy(5, Effect.ALLOW, "payment:**", ["payment.refund"],
                  conditions={"max_amount": 5000})
    d = eng.evaluate(
        ActionRequest("payment.refund", "payment:stripe:refund", metadata={"amount": 9000}), [pol]
    )
    assert d.decision == Decision.DENY


def test_egress_with_secret_is_blocked_even_if_allowed():
    eng = PolicyEngine(block_egress_on_secret=True)
    pol = _policy(6, Effect.ALLOW, "http:**", ["http.post"])
    req = ActionRequest(
        "http.post", "http:api.partner.com/webhook",
        payload={"body": "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
    )
    d = eng.evaluate(req, [pol])
    assert d.decision == Decision.DENY
    assert "exfiltration" in d.reason.lower()


def test_time_window_denies_outside_hours():
    eng = PolicyEngine()
    pol = _policy(8, Effect.ALLOW, "infra:service:*", ["ops.restart"],
                  conditions={"time_window": {"start": "09:00", "end": "17:00"}})
    at_night = datetime(2026, 1, 1, 23, 0, tzinfo=timezone.utc)
    at_noon = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    assert eng.evaluate(ActionRequest("ops.restart", "infra:service:api"), [pol],
                        now=at_night).decision == Decision.DENY
    assert eng.evaluate(ActionRequest("ops.restart", "infra:service:api"), [pol],
                        now=at_noon).decision == Decision.ALLOW


def test_rate_limit_denies_when_exceeded():
    eng = PolicyEngine()
    pol = _policy(9, Effect.ALLOW, "payment:**", ["payment.refund"],
                  conditions={"rate_limit": {"count": 3, "per_seconds": 60}})
    req = ActionRequest("payment.refund", "payment:stripe:refund")
    allowed = eng.evaluate(req, [pol], rate_counter=lambda s: 2)
    denied = eng.evaluate(req, [pol], rate_counter=lambda s: 3)
    assert allowed.decision == Decision.ALLOW
    assert denied.decision == Decision.DENY
