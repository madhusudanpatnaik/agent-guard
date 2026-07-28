"""Tests for the framework-integration adapters (GovernedToolRouter etc.)."""

from contextlib import contextmanager

import pytest
from fastapi.testclient import TestClient

from agentops.main import app
from agentops_sdk import (
    AgentOpsClient,
    AuthorizationDenied,
    DecisionResult,
    GovernedToolRouter,
    govern_langchain_tool,
    govern_tool_fn,
)


# --------------------------------------------------------------------------- #
# Unit tests with a fake client (deterministic, no server)
# --------------------------------------------------------------------------- #

class FakeOps:
    def __init__(self, decision="allow"):
        self.decision = decision
        self.calls: list[dict] = []

    @contextmanager
    def guard(self, action_type, resource, payload=None, metadata=None, wait_for_approval=True):
        self.calls.append(
            {"action_type": action_type, "resource": resource,
             "payload": payload, "metadata": metadata}
        )
        if self.decision != "allow":
            raise AuthorizationDenied(DecisionResult(decision=self.decision, reason="nope"))
        yield DecisionResult(decision="allow", reason="ok")


def test_router_dispatch_allows_and_runs():
    ops = FakeOps("allow")
    router = GovernedToolRouter(ops)
    ran = []
    router.register("lookup", lambda **kw: ran.append(kw) or "result",
                    action_type="tool.lookup", resource="tool:lookup")
    out = router.dispatch("lookup", {"customer_id": 7})
    assert out == "result"
    assert ran == [{"customer_id": 7}]
    assert ops.calls[0]["action_type"] == "tool.lookup"
    assert ops.calls[0]["resource"] == "tool:lookup"
    assert ops.calls[0]["payload"] == {"customer_id": 7}


def test_router_denied_does_not_run_handler():
    ops = FakeOps("deny")
    router = GovernedToolRouter(ops)
    ran = []
    router.register("wipe", lambda **kw: ran.append("BAD"),
                    action_type="tool.wipe", resource="tool:wipe")
    with pytest.raises(AuthorizationDenied):
        router.dispatch("wipe", {})
    assert ran == []  # handler never executed


def test_router_resource_arg_and_amount_arg():
    ops = FakeOps("allow")
    router = GovernedToolRouter(ops)
    router.register("refund", lambda **kw: "ok", action_type="payment.refund",
                    resource_arg="account", amount_arg="amount")
    router.dispatch("refund", {"account": "acct:42", "amount": 250})
    call = ops.calls[0]
    assert call["resource"] == "acct:42"          # resource pulled from args
    assert call["metadata"] == {"amount": 250}    # amount surfaced for policy


def test_router_decorator_registration():
    ops = FakeOps("allow")
    router = GovernedToolRouter(ops)

    @router.tool("greet", action_type="tool.greet", resource="tool:greet")
    def greet(name: str):
        return f"hi {name}"

    assert "greet" in router.names()
    assert router.dispatch("greet", {"name": "Dana"}) == "hi Dana"


def test_router_unknown_tool_raises_keyerror():
    router = GovernedToolRouter(FakeOps("allow"))
    with pytest.raises(KeyError):
        router.dispatch("nope", {})


def test_govern_tool_fn_wraps_callable():
    ops = FakeOps("allow")
    calls = []
    fn = govern_tool_fn(ops, lambda **kw: calls.append(kw) or 1,
                        action_type="tool.x", resource="tool:x")
    assert fn(a=1) == 1
    assert calls == [{"a": 1}]

    denied = govern_tool_fn(FakeOps("deny"), lambda **kw: 1,
                            action_type="tool.x", resource="tool:x")
    with pytest.raises(AuthorizationDenied):
        denied(a=1)


def test_govern_langchain_tool_wraps_func():
    class FakeTool:  # duck-typed LangChain Tool
        name = "search"

        def __init__(self):
            self.func = lambda query: f"results for {query}"

    ops = FakeOps("allow")
    tool = govern_langchain_tool(ops, FakeTool())
    assert tool.func("acme") == "results for acme"
    assert ops.calls[0]["action_type"] == "tool.search"
    assert ops.calls[0]["resource"] == "tool:search"


# --------------------------------------------------------------------------- #
# End-to-end: route a tool call through the REAL control plane
# --------------------------------------------------------------------------- #

def test_router_through_live_plane(client, admin_headers):
    role = client.post("/api/roles", json={"name": "tools"}, headers=admin_headers).json()
    rid = role["id"]
    client.post(f"/api/roles/{rid}/policies", headers=admin_headers, json={
        "effect": "allow", "resource": "tool:lookup", "actions": ["tool.lookup"]})
    client.post(f"/api/roles/{rid}/policies", headers=admin_headers, json={
        "effect": "deny", "resource": "tool:delete_account", "actions": ["tool.delete_account"]})
    agent = client.post("/api/agents", json={"name": "ToolBot", "role_id": rid},
                        headers=admin_headers).json()

    authed = TestClient(app)
    authed.headers.update({"X-API-Key": agent["api_key"]})
    ops = AgentOpsClient("http://testserver", api_key=agent["api_key"], client=authed)

    router = GovernedToolRouter(ops)
    ran: list[str] = []
    router.register("lookup", lambda **kw: ran.append("lookup") or "found",
                    action_type="tool.lookup", resource="tool:lookup")
    router.register("delete_account", lambda **kw: ran.append("DELETED"),
                    action_type="tool.delete_account", resource="tool:delete_account")

    # Allowed tool runs; denied tool is blocked before the handler executes.
    assert router.dispatch("lookup", {"id": 1}) == "found"
    with pytest.raises(AuthorizationDenied):
        router.dispatch("delete_account", {"id": 1})
    assert ran == ["lookup"]
