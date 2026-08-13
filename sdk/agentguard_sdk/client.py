"""Client SDK for the AgentGuard control plane.

Two different guarantees live behind a similar-looking API — pick deliberately:

**Enforced mode** — the plane holds the upstream credential and makes the call
itself; the agent physically cannot reach the upstream except through it::

    from agentguard_sdk import AgentGuardClient

    ops = AgentGuardClient("http://localhost:8080", api_key="agentguard_sk_...")
    customer = ops.call("crm", "GET", "/customers/1042")   # plane injects the credential

**Advisory mode** (``guard()`` / ``@governed``) — the agent still holds its own
credentials and performs the side effect itself; AgentGuard only sees the action
if the agent's own code chooses to ask first. This is a real audit trail and
DLP scan for an agent you already trust to cooperate — it is not a security
boundary against one you don't, since nothing stops that agent from simply not
calling ``guard()`` at all::

    with ops.guard("payment.refund", "payment:stripe:refund", metadata={"amount": 250}):
        stripe.Refund.create(...)   # only runs if allowed (or approved)

For an agent you don't fully trust and can't modify, prefer the transparent
forward proxy (``agentguard proxy``) instead of either — it requires no agent
code and the agent has no way to opt out. See the README's "How your agents
integrate" section for the full comparison.
"""

from __future__ import annotations

import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from functools import wraps
from typing import Any, Callable, Iterator

import httpx


class Decision:
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


@dataclass
class DecisionResult:
    decision: str
    reason: str
    request_id: int | None = None
    approval_id: int | None = None
    matched_policy_id: int | None = None
    obligations: list[str] = field(default_factory=list)
    dlp_findings: list[dict] = field(default_factory=list)
    risk_score: int | None = None
    risk_factors: list[str] = field(default_factory=list)
    audit_seq: int | None = None
    audit_hash: str | None = None

    @property
    def allowed(self) -> bool:
        return self.decision == Decision.ALLOW

    @classmethod
    def from_response(cls, data: dict[str, Any]) -> "DecisionResult":
        return cls(
            decision=data.get("decision", Decision.DENY),
            reason=data.get("reason", ""),
            request_id=data.get("request_id"),
            approval_id=data.get("approval_id"),
            matched_policy_id=data.get("matched_policy_id"),
            obligations=data.get("obligations", []),
            dlp_findings=data.get("dlp_findings", []),
            risk_score=data.get("risk_score"),
            risk_factors=data.get("risk_factors", []),
            audit_seq=data.get("audit_seq"),
            audit_hash=data.get("audit_hash"),
        )


class AuthorizationDenied(Exception):
    """Raised by :meth:`AgentGuardClient.guard` when an action is not permitted."""

    def __init__(self, result: DecisionResult):
        self.result = result
        super().__init__(f"{result.decision}: {result.reason}")


class AgentGuardClient:
    def __init__(
        self,
        base_url: str = "http://localhost:8080",
        api_key: str | None = None,
        *,
        timeout: float = 10.0,
        client: httpx.Client | None = None,
    ):
        if not api_key:
            raise ValueError("api_key is required")
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self._client = client or httpx.Client(
            base_url=self.base_url,
            headers={"X-API-Key": api_key},
            timeout=timeout,
        )

    # -- core API ---------------------------------------------------------
    def authorize(
        self,
        action_type: str,
        resource: str,
        payload: Any = None,
        metadata: dict[str, Any] | None = None,
    ) -> DecisionResult:
        resp = self._client.post(
            "/api/v1/gateway/authorize",
            json={
                "action_type": action_type,
                "resource": resource,
                "payload": payload,
                "metadata": metadata or {},
            },
        )
        resp.raise_for_status()
        return DecisionResult.from_response(resp.json())

    def execute(
        self,
        connector: str,
        method: str = "GET",
        path: str = "/",
        *,
        body: Any = None,
        headers: dict[str, str] | None = None,
        metadata: dict[str, Any] | None = None,
        approval_id: int | None = None,
    ) -> dict[str, Any]:
        """Enforced call: the plane authorizes AND performs the upstream request.

        Returns the full execution envelope (executed flag, decision, status_code,
        redacted response_body, DLP findings). The agent never holds the upstream
        credential, so it cannot reach the upstream except through this call.
        """
        resp = self._client.post(
            "/api/v1/gateway/execute",
            json={
                "connector": connector,
                "method": method,
                "path": path,
                "headers": headers or {},
                "body": body,
                "metadata": metadata or {},
                "approval_id": approval_id,
            },
        )
        resp.raise_for_status()
        return resp.json()

    def call(
        self,
        connector: str,
        method: str = "GET",
        path: str = "/",
        *,
        body: Any = None,
        metadata: dict[str, Any] | None = None,
    ) -> Any:
        """Convenience wrapper: return the response body or raise if not executed."""
        result = self.execute(connector, method, path, body=body, metadata=metadata)
        if not result.get("executed"):
            raise AuthorizationDenied(DecisionResult.from_response(result))
        return result.get("response_body")

    def query(
        self,
        connector: str,
        sql: str,
        *,
        params: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
        approval_id: int | None = None,
    ) -> dict[str, Any]:
        """Enforced read-only SQL: the plane holds the DSN and runs the query.

        Returns the full envelope (executed, decision, columns, rows, row_count,
        DLP findings). Only SELECT/WITH are permitted; rows are DLP-redacted.
        """
        resp = self._client.post(
            "/api/v1/gateway/query",
            json={
                "connector": connector,
                "sql": sql,
                "params": params or {},
                "metadata": metadata or {},
                "approval_id": approval_id,
            },
        )
        resp.raise_for_status()
        return resp.json()

    def sql(
        self,
        connector: str,
        sql: str,
        *,
        params: dict[str, Any] | None = None,
    ) -> list[dict]:
        """Convenience wrapper: return the (redacted) rows, or raise if not executed."""
        result = self.query(connector, sql, params=params)
        if not result.get("executed"):
            raise AuthorizationDenied(DecisionResult.from_response(result))
        return result.get("rows", [])

    def write(
        self,
        connector: str,
        sql: str,
        *,
        params: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
        approval_id: int | None = None,
    ) -> dict[str, Any]:
        """Governed write (INSERT/UPDATE/DELETE) against a *writable* DB connector.

        Runs in a transaction on the plane; rolled back if it would exceed the
        connector's row cap. Returns the envelope (executed, decision, rows_affected).
        """
        resp = self._client.post(
            "/api/v1/gateway/write",
            json={
                "connector": connector,
                "sql": sql,
                "params": params or {},
                "metadata": metadata or {},
                "approval_id": approval_id,
            },
        )
        resp.raise_for_status()
        return resp.json()

    def publish(
        self,
        connector: str,
        topic: str,
        message: Any,
        *,
        key: str | None = None,
        metadata: dict[str, Any] | None = None,
        approval_id: int | None = None,
    ) -> dict[str, Any]:
        """Governed message-broker publish (Kafka/RabbitMQ/SQS).

        The plane authorizes + DLP-scans the message and holds the broker
        credential; the agent never connects to the broker directly. Returns the
        envelope (executed, decision, request_dlp_findings, ...).
        """
        resp = self._client.post(
            "/api/v1/gateway/publish",
            json={
                "connector": connector,
                "topic": topic,
                "message": message,
                "key": key,
                "metadata": metadata or {},
                "approval_id": approval_id,
            },
        )
        resp.raise_for_status()
        return resp.json()

    def get_approval(self, approval_id: int) -> dict[str, Any]:
        resp = self._client.get(f"/api/v1/gateway/approvals/{approval_id}")
        resp.raise_for_status()
        return resp.json()

    def wait_for_approval(
        self, approval_id: int, *, timeout: float = 120.0, interval: float = 2.0
    ) -> str:
        """Poll an approval until it is resolved. Returns the final status."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            status = self.get_approval(approval_id).get("status", "pending")
            if status != "pending":
                return status
            time.sleep(interval)
        return "pending"

    def whoami(self) -> dict[str, Any]:
        resp = self._client.get("/api/v1/gateway/whoami")
        resp.raise_for_status()
        return resp.json()

    # -- ergonomic guard --------------------------------------------------
    @contextmanager
    def guard(
        self,
        action_type: str,
        resource: str,
        payload: Any = None,
        metadata: dict[str, Any] | None = None,
        *,
        wait_for_approval: bool = True,
        approval_timeout: float = 120.0,
    ) -> Iterator[DecisionResult]:
        """Context manager that only enters the block if the action is permitted.

        * ``allow``            -> body runs.
        * ``require_approval`` -> optionally block until a human resolves it; runs
                                  only if approved, otherwise raises.
        * ``deny``             -> raises :class:`AuthorizationDenied`.

        Advisory mode: the body still runs with whatever credentials your own
        code already holds. This is real for an agent that cooperates — it is
        not a barrier against one that doesn't, since nothing stops the caller
        from performing the side effect without ever entering this block. For
        an agent you don't fully trust, use enforced mode (``execute``/``call``/
        ``query``/``sql``/``write``/``publish``) or the transparent proxy instead.
        """
        result = self.authorize(action_type, resource, payload, metadata)

        if result.decision == Decision.REQUIRE_APPROVAL and wait_for_approval and result.approval_id:
            final = self.wait_for_approval(result.approval_id, timeout=approval_timeout)
            if final == "approved":
                result.decision = Decision.ALLOW
            else:
                result.decision = Decision.DENY
                result.reason = f"approval {final}"

        if not result.allowed:
            raise AuthorizationDenied(result)
        yield result

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "AgentGuardClient":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def governed(
    client: AgentGuardClient,
    *,
    action_type: str,
    resource: str | None = None,
    resource_arg: str | None = None,
) -> Callable:
    """Decorator that governs every call to a tool/function.

    ``resource`` is a static resource string; alternatively ``resource_arg``
    names a keyword argument whose value becomes the resource.

    Built on :meth:`AgentGuardClient.guard` — advisory mode, not a security
    boundary. See that method's docstring before using this on an agent you
    don't fully trust to actually be calling the decorated function.
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            res = resource
            if resource_arg is not None:
                res = str(kwargs.get(resource_arg, resource_arg))
            with client.guard(action_type, res or func.__name__, payload=kwargs):
                return func(*args, **kwargs)

        return wrapper

    return decorator
