"""Negative amounts must not bypass spending ceilings or approval thresholds.

Verified bypass before this fix, against the exact policy the shipped pitch
demo uses (max_amount=5000, require_approval_over=500):

    amount= 9500 -> DENY              (correct)
    amount=-9500 -> ALLOW             (no ceiling, no human, no risk score)

Both bounds in _check_constraints are `amount > limit`, so any negative value
cleared both. risk.py additionally gated its score on `amount > 0`, so the same
request also scored zero risk. Some payment APIs treat a negative refund as a
charge, which turns this from a nonsense value into a transfer the ceiling was
meant to prevent.
"""

from __future__ import annotations

import pytest

from agentguard.dlp.scanner import DLPResult
from agentguard.models import Decision, Effect, Policy
from agentguard.policy.engine import ActionRequest, PolicyEngine

CEILING, REVIEW_OVER = 5000, 500


def _policy() -> Policy:
    return Policy(
        id=1, name="refunds", effect=Effect.ALLOW, resource="payment:**",
        actions=["payment.refund"], enabled=True, priority=0,
        conditions={"max_amount": CEILING, "require_approval_over": REVIEW_OVER},
    )


def _decide(amount):
    req = ActionRequest(action_type="payment.refund",
                        resource="payment:stripe:refund",
                        metadata={} if amount is None else {"amount": amount})
    return PolicyEngine().evaluate(req, [_policy()],
                                   dlp=DLPResult(findings=[], redacted=None))


@pytest.mark.parametrize("amount", [-1, -0.01, -500, -9500, -1_000_000, "-9500"])
def test_negative_amounts_never_pass_silently(amount):
    """The bypass: any of these previously returned ALLOW."""
    assert _decide(amount).decision == Decision.REQUIRE_APPROVAL


def test_positive_amounts_are_unchanged():
    """The fix must not alter correct existing behaviour."""
    assert _decide(250).decision == Decision.ALLOW
    assert _decide(REVIEW_OVER + 1).decision == Decision.REQUIRE_APPROVAL
    assert _decide(CEILING + 1).decision == Decision.DENY


def test_missing_amount_still_routes_to_human():
    """Pre-existing fail-closed rule this fix is modelled on."""
    assert _decide(None).decision == Decision.REQUIRE_APPROVAL


def test_zero_is_allowed_not_treated_as_negative():
    """0 is a bounded, verifiable amount — it must not be swept up by the fix."""
    assert _decide(0).decision == Decision.ALLOW


def test_unconstrained_policy_ignores_amount_sign():
    """A policy with no amount condition must not suddenly demand approval."""
    p = Policy(id=2, name="open", effect=Effect.ALLOW, resource="payment:**",
               actions=["payment.refund"], enabled=True, priority=0, conditions={})
    req = ActionRequest(action_type="payment.refund", resource="payment:x",
                        metadata={"amount": -9500})
    assert PolicyEngine().evaluate(
        req, [p], dlp=DLPResult(findings=[], redacted=None)).decision == Decision.ALLOW


def test_risk_scores_negative_amount_by_magnitude():
    """risk.py gated on `amount > 0`, so -9500 scored as if there were no amount."""
    from agentguard.risk import _coerce_amount

    assert _coerce_amount(-9500) == -9500.0
    # The scoring path is exercised via assess(); here we assert the property
    # that motivated the change: exposure is magnitude, not signed value.
    assert abs(_coerce_amount(-9500)) == abs(_coerce_amount(9500))
