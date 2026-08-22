"""Unknown policy condition keys must be rejected at write time.

An unrecognised key in `conditions` is simply never read by the policy engine,
so for a security control it FAILS OPEN. Proved before this validation existed,
against a policy the operator believed capped spending at $5,000:

    {"max_amount":  5000}  ->  $999,999  DENY    (correct)
    {"max_ammount": 5000}  ->  $999,999  ALLOW   (one typo, ceiling gone)
    {"maxAmount":   5000}  ->  $999,999  ALLOW
    {"require_approval_ovr": 5} -> $999,999 ALLOW

The console authors this field as a raw JSON textarea, so the typo is one
keystroke away, the policy saves successfully, and nothing downstream ever
reveals that the constraint is inert.

This also removes an inconsistency: a malformed VALUE already failed closed
(`{"max_amount": "abc"}` routes to human review in _check_constraints), while
an unknown KEY failed open.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from agentguard.schemas import _VALID_POLICY_CONDITIONS, PolicyIn


@pytest.mark.parametrize("key", sorted(_VALID_POLICY_CONDITIONS))
def test_every_documented_key_is_accepted(key):
    """The allowlist must not reject a key the engine actually honours."""
    assert PolicyIn(conditions={key: {}}).conditions == {key: {}}


def test_allowlist_matches_what_the_engine_reads():
    """Guard against the allowlist and the engine drifting apart.

    If someone teaches the engine a new condition key without adding it here,
    that key becomes un-writable through the API; if they remove one, a dead
    key stays writable. Both are caught by pinning the set explicitly.
    """
    assert _VALID_POLICY_CONDITIONS == {
        "max_amount", "require_approval_over", "rate_limit",
        "time_window", "attributes", "risk_step_up",
    }


@pytest.mark.parametrize("bad", [
    "max_ammount", "maxAmount", "max_amount_usd", "require_approval_ovr",
    "MAX_AMOUNT", "rate_limits", "timewindow", "wibble",
])
def test_unknown_keys_are_rejected(bad):
    with pytest.raises(ValidationError):
        PolicyIn(conditions={bad: 5000})


def test_error_names_the_key_the_valid_set_and_a_suggestion():
    """The message has to be actionable — this is an operator typo, at 2am."""
    with pytest.raises(ValidationError) as exc:
        PolicyIn(conditions={"max_ammount": 5000})
    msg = str(exc.value)
    assert "max_ammount" in msg, "must name the offending key"
    assert "did you mean 'max_amount'" in msg, "must suggest the intended key"
    assert "max_amount" in msg and "rate_limit" in msg, "must list valid keys"


def test_a_valid_key_alongside_a_typo_still_rejects():
    """Partial correctness must not mask the broken half."""
    with pytest.raises(ValidationError):
        PolicyIn(conditions={"max_amount": 5000, "require_approval_ovr": 500})


def test_empty_conditions_are_fine():
    assert PolicyIn(conditions={}).conditions == {}


def test_rejected_over_the_api(client, admin_headers):
    """End-to-end: the API refuses the write rather than storing a dead policy."""
    role = client.post("/api/roles", json={"name": "typo-role"},
                       headers=admin_headers).json()
    r = client.post(f"/api/roles/{role['id']}/policies", headers=admin_headers,
                    json={"effect": "allow", "resource": "payment:**",
                          "actions": ["payment.refund"],
                          "conditions": {"max_ammount": 5000}})
    assert r.status_code == 422, r.text
    assert "max_ammount" in r.text

    # And the correctly-spelled policy is still accepted.
    ok = client.post(f"/api/roles/{role['id']}/policies", headers=admin_headers,
                     json={"effect": "allow", "resource": "payment:**",
                           "actions": ["payment.refund"],
                           "conditions": {"max_amount": 5000}})
    assert ok.status_code == 201, ok.text
