"""ADVISORY-mode demo: an autonomous agent that clears every action with AgentGuard.

This is the weaker of the two SDK modes: the agent below still performs each
action itself and is trusted to honor the decision. It's real for an agent
that cooperates — nothing here would stop this same agent from skipping
``ops.guard()`` and just doing the action anyway. For an agent you don't fully
trust, see enforcing_demo.py (the plane holds the credential instead) or
proxy_demo.py (governs the agent's raw HTTP with zero SDK code, no opt-out).

Prereqs::

    agentguard serve            # in one terminal
    agentguard seed             # prints agent API keys

Then::

    AGENTGUARD_API_KEY=agentguard_sk_...  python examples/demo_agent.py
"""

from __future__ import annotations

import os
import sys

# Make the local SDK importable when running from a source checkout.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "sdk"))

from agentguard_sdk import AgentGuardClient, AuthorizationDenied  # noqa: E402

BASE_URL = os.environ.get("AGENTGUARD_URL", "http://localhost:8080")
API_KEY = os.environ.get("AGENTGUARD_API_KEY")


def try_action(ops: AgentGuardClient, label: str, **kw) -> None:
    try:
        with ops.guard(wait_for_approval=False, **kw) as decision:
            print(f"  ✅ {label}: ALLOWED — {decision.reason}")
    except AuthorizationDenied as denied:
        r = denied.result
        tag = "⏸  NEEDS APPROVAL" if r.decision == "require_approval" else "⛔ DENIED"
        print(f"  {tag} {label}: {r.reason}")
        if r.dlp_findings:
            kinds = ", ".join(f"{f['detector']}({f['severity']})" for f in r.dlp_findings)
            print(f"      DLP: {kinds}")


def main() -> int:
    if not API_KEY:
        print("Set AGENTGUARD_API_KEY (from `agentguard seed`).")
        return 1

    ops = AgentGuardClient(BASE_URL, api_key=API_KEY)
    print(f"Authenticated as: {ops.whoami()}\n")

    print("Attempting a spread of actions:")
    try_action(ops, "read a customer record",
               action_type="db.read", resource="db:customers:1042",
               payload={"query": "SELECT * FROM customers WHERE id=1042"})

    try_action(ops, "write to the CRM",
               action_type="db.write", resource="db:customers:1042",
               payload={"set": {"tier": "vip"}})

    try_action(ops, "email a customer's SSN externally",
               action_type="http.post", resource="http:evil.example/collect",
               payload={"body": "SSN 452-11-9832, card 4111111111111111"})

    try_action(ops, "refund $250",
               action_type="payment.refund", resource="payment:stripe:refund",
               metadata={"amount": 250}, payload={"invoice": "inv_1"})

    try_action(ops, "refund $2,000 (over approval threshold)",
               action_type="payment.refund", resource="payment:stripe:refund",
               metadata={"amount": 2000}, payload={"invoice": "inv_2"})

    ops.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
