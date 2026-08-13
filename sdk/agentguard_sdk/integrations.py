"""Framework integrations — make existing agent tools governed with a few lines.

The point of AgentGuard is that agents route their actions through the control
plane. This module provides thin, dependency-free adapters so the common agent
frameworks do that automatically:

* :class:`GovernedToolRouter` — the universal primitive for **tool / function
  calling** (OpenAI function calling, Anthropic tool use, and MCP tool servers
  all share the "dispatch a named tool with JSON arguments" shape). Register your
  tools once with the action + resource they represent; ``dispatch`` authorizes
  against the plane *before* your handler runs, and raises if it is denied.

* :func:`govern_tool_fn` — wrap any plain callable so each call is authorized.

* :func:`govern_langchain_tool` — wrap a LangChain tool (duck-typed, so LangChain
  is **not** a required dependency) so its execution is authorized first.

For tools that reach external systems, call ``ops.execute(...)`` (HTTP) or
``ops.query(...)`` (SQL) *inside* the handler — those are enforced end-to-end and
the plane holds the credentials. The router governs the *decision* to run.
"""

from __future__ import annotations

from typing import Any, Callable

from .client import AgentGuardClient, AuthorizationDenied  # noqa: F401  (re-exported)


def govern_tool_fn(
    ops: AgentGuardClient,
    fn: Callable,
    *,
    action_type: str,
    resource: str,
    metadata_arg: str | None = None,
    wait_for_approval: bool = True,
) -> Callable:
    """Return a wrapped ``fn`` that authorizes with the plane before executing.

    Raises :class:`AuthorizationDenied` if the plane denies (or an approval is
    declined). The tool's keyword arguments are sent as the action payload so the
    DLP scanner can inspect them.

    Advisory mode (built on :meth:`AgentGuardClient.guard`): ``fn`` still performs
    the side effect, so this governs code that calls the wrapper — not ``fn``
    itself if something else still has a direct reference to it.
    """

    def wrapper(**kwargs: Any) -> Any:
        metadata = kwargs.get(metadata_arg) if metadata_arg else None
        with ops.guard(
            action_type, resource, payload=kwargs,
            metadata=metadata if isinstance(metadata, dict) else None,
            wait_for_approval=wait_for_approval,
        ):
            return fn(**kwargs)

    wrapper.__name__ = getattr(fn, "__name__", "governed_tool")
    wrapper.__doc__ = getattr(fn, "__doc__", None)
    return wrapper


class GovernedToolRouter:
    """Authorize-then-dispatch router for tool/function-calling agents.

    Works with any framework that produces a ``(tool_name, arguments_dict)`` —
    OpenAI function calling, Anthropic tool use, and MCP tool servers::

        router = GovernedToolRouter(ops)

        @router.tool("issue_refund", action_type="payment.refund",
                     resource="payment:stripe:refund", amount_arg="amount")
        def issue_refund(invoice: str, amount: float): ...

        # when the model asks to call a tool:
        result = router.dispatch(call.name, call.arguments)   # authorized first

    Advisory mode under the hood (``dispatch`` calls
    :meth:`AgentGuardClient.guard`): your own handler function still performs the
    side effect, so this is a real audit trail and DLP scan for a model/agent
    you trust to only call tools through this router, not a barrier against
    code that calls ``issue_refund(...)`` directly instead of via ``dispatch``.
    """

    def __init__(self, ops: AgentGuardClient, *, wait_for_approval: bool = True):
        self.ops = ops
        self.wait_for_approval = wait_for_approval
        self._tools: dict[str, dict] = {}

    def register(
        self,
        name: str,
        fn: Callable,
        *,
        action_type: str | None = None,
        resource: str | None = None,
        resource_arg: str | None = None,
        amount_arg: str | None = None,
    ) -> None:
        self._tools[name] = {
            "fn": fn,
            "action_type": action_type or f"tool.{name}",
            "resource": resource,
            "resource_arg": resource_arg,
            "amount_arg": amount_arg,
        }

    def tool(
        self,
        name: str,
        *,
        action_type: str | None = None,
        resource: str | None = None,
        resource_arg: str | None = None,
        amount_arg: str | None = None,
    ) -> Callable:
        """Decorator form of :meth:`register`."""

        def deco(fn: Callable) -> Callable:
            self.register(
                name, fn, action_type=action_type, resource=resource,
                resource_arg=resource_arg, amount_arg=amount_arg,
            )
            return fn

        return deco

    def names(self) -> list[str]:
        return list(self._tools)

    def dispatch(self, name: str, arguments: dict | None = None) -> Any:
        """Authorize the named tool call against the plane, then run it if allowed.

        Raises :class:`KeyError` for an unknown tool and
        :class:`AuthorizationDenied` if the plane refuses.
        """
        if name not in self._tools:
            raise KeyError(f"unknown tool '{name}'")
        spec = self._tools[name]
        args = arguments or {}

        resource = spec["resource"]
        if spec["resource_arg"] is not None:
            resource = str(args.get(spec["resource_arg"], spec["resource_arg"]))
        resource = resource or f"tool:{name}"

        metadata = None
        if spec["amount_arg"] is not None and spec["amount_arg"] in args:
            metadata = {"amount": args[spec["amount_arg"]]}

        with self.ops.guard(
            spec["action_type"], resource, payload=args, metadata=metadata,
            wait_for_approval=self.wait_for_approval,
        ):
            return spec["fn"](**args)


def govern_langchain_tool(
    ops: AgentGuardClient,
    tool: Any,
    *,
    action_type: str | None = None,
    resource: str | None = None,
) -> Any:
    """Wrap a LangChain tool so its execution is authorized by the plane first.

    Duck-typed — LangChain is not imported here. It wraps the tool's underlying
    callable (``.func`` on ``Tool`` / ``StructuredTool``) in place and returns the
    same tool object, so it drops straight into an existing agent.

    Advisory mode (built on :meth:`AgentGuardClient.guard`): the tool's own
    function still performs the side effect once authorized.
    """
    name = getattr(tool, "name", getattr(tool, "__name__", "tool"))
    action_type = action_type or f"tool.{name}"
    resource = resource or f"tool:{name}"

    target = getattr(tool, "func", None)
    if target is None:
        raise TypeError(
            "govern_langchain_tool expects a tool with a `.func` attribute "
            "(e.g. langchain Tool/StructuredTool); wrap the function with "
            "govern_tool_fn and rebuild the tool instead."
        )

    def guarded(*args: Any, **kwargs: Any) -> Any:
        payload = kwargs or ({"input": args[0]} if len(args) == 1 else {"args": list(args)})
        with ops.guard(action_type, resource, payload=payload):
            return target(*args, **kwargs)

    tool.func = guarded
    return tool
