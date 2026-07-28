"""AgentOps — governed tool-calling demo.

Shows how a few lines make an existing tool-calling agent governed. The
``GovernedToolRouter`` sits between the model's tool calls and your handlers —
it works with OpenAI function calling, Anthropic tool use, and MCP tool servers,
which all produce the same ``(tool_name, arguments)`` shape.

Here we simulate the tool calls a model would emit; each is authorized against
the control plane BEFORE the handler runs. Run it (after `make seed` and
`make serve`):

    python examples/toolcalling_demo.py
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "sdk"))

import httpx  # noqa: E402

from agentops_sdk import AgentOpsClient, AuthorizationDenied, GovernedToolRouter  # noqa: E402

URL = os.environ.get("AGENTOPS_URL", "http://localhost:8080")
ADMIN_EMAIL = os.environ.get("AGENTOPS_ADMIN_EMAIL", "admin@agentops.local")
ADMIN_PASSWORD = os.environ.get("AGENTOPS_ADMIN_PASSWORD", "admin")


def _die(msg: str) -> None:
    print(f"\n✗ {msg}")
    raise SystemExit(1)


def _provision_assistant(http: httpx.Client) -> str:
    """Create a role with per-tool policies + an agent, and return its API key."""
    try:
        r = http.post("/api/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
    except httpx.HTTPError:
        _die(f"Could not reach the plane at {URL}. Is `make serve` running?")
    if r.status_code != 200:
        _die("Admin login failed. Set AGENTOPS_ADMIN_PASSWORD if you changed it.")
    headers = {"Authorization": f"Bearer {r.json()['access_token']}"}

    # Idempotent: reuse the demo role if it already exists (so re-runs don't 409).
    existing = next((x for x in http.get("/api/roles", headers=headers).json()
                     if x["name"] == "ai-assistant-demo"), None)
    if existing:
        rid = existing["id"]
    else:
        rid = http.post("/api/roles", headers=headers,
                        json={"name": "ai-assistant-demo",
                              "description": "Tool-calling assistant"}).json()["id"]
        for p in [
            {"name": "weather", "effect": "allow", "resource": "tool:get_weather",
             "actions": ["tool.get_weather"]},
            {"name": "refund-with-approval", "effect": "allow", "resource": "payment:refund",
             "actions": ["payment.refund"], "conditions": {"require_approval_over": 100}},
            {"name": "no-delete-user", "effect": "deny", "resource": "tool:delete_user",
             "actions": ["tool.delete_user"]},
        ]:
            http.post(f"/api/roles/{rid}/policies", headers=headers, json=p)

    agent = http.post("/api/agents", headers=headers,
                      json={"name": "AssistantBot", "role_id": rid}).json()
    return agent["api_key"]


# ---- the agent's actual tool handlers (ordinary functions) -----------------

def get_weather(city: str) -> str:
    return f"{city}: 72°F, sunny"


def issue_refund(invoice: str, amount: float) -> str:
    return f"refunded ${amount} for {invoice}"


def delete_user(user_id: int) -> str:
    return f"deleted user {user_id}"


def main() -> int:
    with httpx.Client(base_url=URL, timeout=10) as http:
        api_key = _provision_assistant(http)

    ops = AgentOpsClient(URL, api_key=api_key)
    # wait_for_approval=False so an approval-required call is reported, not blocking.
    router = GovernedToolRouter(ops, wait_for_approval=False)
    router.register("get_weather", get_weather,
                    action_type="tool.get_weather", resource="tool:get_weather")
    router.register("issue_refund", issue_refund,
                    action_type="payment.refund", resource="payment:refund", amount_arg="amount")
    router.register("delete_user", delete_user,
                    action_type="tool.delete_user", resource="tool:delete_user")

    # Simulated model tool calls (what OpenAI/Anthropic/MCP would emit).
    tool_calls = [
        ("get_weather", {"city": "San Francisco"}),
        ("issue_refund", {"invoice": "INV-42", "amount": 500}),   # over the $100 review line
        ("delete_user", {"user_id": 1042}),                       # policy-denied
    ]

    print("Governed tool-calling — each model tool call is authorized first:\n")
    for name, args in tool_calls:
        try:
            result = router.dispatch(name, args)
            print(f"  ✓ {name}({args}) → ran → {result}")
        except AuthorizationDenied as denied:
            print(f"  ✗ {name}({args}) → BLOCKED → {denied.result.decision}: {denied.result.reason}")

    ops.close()
    print("\nEvery call above — allowed or blocked — is in the audit ledger.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
