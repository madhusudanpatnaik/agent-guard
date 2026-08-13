"""Tests for the security-hardening fixes from the adversarial review."""

from agentguard.config import DEV_SECRET_DEFAULT, Settings
from agentguard.models import Decision, Effect, Policy
from agentguard.policy.engine import ActionRequest, PolicyEngine


def _policy(pid, effect, resource, actions, **kw):
    return Policy(
        id=pid, role_id=1, name=kw.get("name", ""), effect=effect, resource=resource,
        actions=actions, conditions=kw.get("conditions", {}),
        require_approval=kw.get("require_approval", False),
        priority=kw.get("priority", 0), enabled=kw.get("enabled", True),
    )


# --- production configuration guard -----------------------------------------

def test_production_guard_flags_default_secret_and_password():
    s = Settings(environment="production", secret_key=DEV_SECRET_DEFAULT,
                 bootstrap_admin_password="admin")
    problems = s.production_problems()
    assert len(problems) == 2
    assert any("SECRET_KEY" in p for p in problems)
    assert any("PASSWORD" in p for p in problems)


def test_production_guard_flags_short_secret():
    s = Settings(environment="production", secret_key="tooshort",
                 bootstrap_admin_password="a-strong-password")
    assert any("SECRET_KEY" in p for p in s.production_problems())


def test_production_guard_passes_with_strong_config():
    s = Settings(environment="production", secret_key="x" * 48,
                 bootstrap_admin_password="a-strong-password")
    assert s.production_problems() == []


def test_dev_environment_never_blocks():
    s = Settings(environment="development", secret_key=DEV_SECRET_DEFAULT,
                 bootstrap_admin_password="admin")
    assert s.production_problems() == []


# --- policy fail-closed behavior --------------------------------------------

def test_amount_constrained_action_without_amount_requires_approval():
    eng = PolicyEngine()
    pol = _policy(1, Effect.ALLOW, "payment:**", ["payment.refund"],
                  conditions={"max_amount": 5000})
    # No amount supplied -> must not silently pass the ceiling.
    d = eng.evaluate(ActionRequest("payment.refund", "payment:stripe:refund"), [pol])
    assert d.decision == Decision.REQUIRE_APPROVAL


def test_malformed_time_window_fails_closed():
    eng = PolicyEngine()
    pol = _policy(2, Effect.ALLOW, "infra:service:*", ["ops.restart"],
                  conditions={"time_window": {"start": "not-a-time"}})
    d = eng.evaluate(ActionRequest("ops.restart", "infra:service:api"), [pol])
    assert d.decision == Decision.DENY


def test_broadened_egress_scheme_blocks_secret():
    # A scheme that was previously unlisted (gs://) must still count as egress.
    eng = PolicyEngine(block_egress_on_secret=True)
    pol = _policy(3, Effect.ALLOW, "gs:**", ["storage.write"])
    req = ActionRequest(
        "storage.write", "gs:my-bucket/dump",
        payload={"k": "AKIAIOSFODNN7EXAMPLE"},
    )
    assert eng.evaluate(req, [pol]).decision == Decision.DENY
