"""External policy-as-code evaluators — OPA (Rego) and Cedar.

The built-in :class:`~agentops.policy.engine.PolicyEngine` is fast, pure, and
dependency-free, but large enterprises often want to express authorization in a
dedicated policy language governed by their platform team. This module lets a
deployment delegate the allow/deny decision to an external engine over HTTP,
while AgentOps still owns everything around it — DLP exfiltration blocking,
the audit ledger, approvals, alerts, quotas.

* **OPA** (``policy_engine=opa``): POSTs ``{"input": <decision-input>}`` to the
  configured OPA data URL (e.g. ``/v1/data/agentops/authz``) and reads back
  ``{"result": ...}``. The result may be a bare boolean (allow) or an object
  ``{"allow": bool, "require_approval": bool, "reason": str}``.
* **Cedar** (``policy_engine=cedar``): POSTs the decision input to a Cedar
  authorization sidecar exposing ``/authorize`` and reads ``{"decision":
  "Allow"|"Deny", "reasons": [...]}``.

The decision input includes the action, resource, ABAC attributes, and a
summary of the DLP findings, so external policies can reason over all of them.
On any transport/parse error the evaluator fails **closed** (deny) unless
``policy_engine_fail_open`` is set — a policy service outage must not silently
grant access.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from ..config import get_settings
from ..dlp.scanner import DLPResult
from ..models import Decision
from .engine import ActionRequest, PolicyDecision

_log = logging.getLogger("agentops.policy.external")


def _decision_input(req: ActionRequest, dlp: DLPResult | None) -> dict[str, Any]:
    findings = dlp.findings_as_dicts() if dlp else []
    return {
        "action_type": req.action_type,
        "resource": req.resource,
        "is_egress": req.is_egress(),
        "attributes": req.attributes or {},
        "metadata": req.metadata or {},
        "dlp": {
            "has_findings": bool(findings),
            "blocking": bool(dlp.blocking) if dlp else False,
            "detectors": sorted({f["detector"] for f in findings}),
            "max_severity": dlp.max_severity if dlp else None,
        },
    }


class ExternalPolicyEngine:
    """Delegates the RBAC decision to OPA or Cedar; keeps DLP egress blocking."""

    def __init__(self, *, kind: str, url: str, fail_open: bool,
                 block_egress_on_secret: bool, client: httpx.Client | None = None):
        self.kind = kind.lower()
        self.url = url
        self.fail_open = fail_open
        self.block_egress_on_secret = block_egress_on_secret
        self._client = client

    def _post(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self._client is not None:
            resp = self._client.post(self.url, json=payload, timeout=3.0)
        else:
            resp = httpx.post(self.url, json=payload, timeout=3.0)
        resp.raise_for_status()
        return resp.json()

    def evaluate(self, req: ActionRequest, dlp: DLPResult | None = None) -> PolicyDecision:
        obligations: list[str] = ["redact_payload"] if (dlp and dlp.has_findings) else []

        # DLP exfiltration guard applies regardless of the external verdict —
        # secrets must never leave even if a Rego/Cedar policy would allow it.
        if self.block_egress_on_secret and req.is_egress() and dlp and dlp.blocking:
            leaked = ", ".join(sorted({f.detector for f in dlp.findings}))
            return PolicyDecision(
                Decision.DENY,
                f"Data-exfiltration prevented: sensitive data ({leaked}) in an "
                f"outbound '{req.action_type}' to {req.resource}.",
                obligations=obligations, dlp=dlp,
            )

        try:
            if self.kind == "opa":
                decision = self._eval_opa(req, dlp)
            elif self.kind == "cedar":
                decision = self._eval_cedar(req, dlp)
            else:
                raise ValueError(f"unknown external policy engine {self.kind!r}")
        except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
            if self.fail_open:
                _log.warning("external policy engine error (%s); failing OPEN", exc)
                return PolicyDecision(Decision.ALLOW,
                                      f"External policy engine unavailable; fail-open. ({exc})",
                                      obligations=obligations, dlp=dlp)
            _log.warning("external policy engine error (%s); failing CLOSED", exc)
            return PolicyDecision(Decision.DENY,
                                  f"External policy engine unavailable; fail-closed. ({exc})",
                                  obligations=obligations, dlp=dlp)

        decision.obligations = obligations
        decision.dlp = dlp
        return decision

    def _eval_opa(self, req: ActionRequest, dlp: DLPResult | None) -> PolicyDecision:
        data = self._post({"input": _decision_input(req, dlp)})
        result = data.get("result")
        if isinstance(result, bool):
            return (
                PolicyDecision(Decision.ALLOW, "Allowed by OPA policy.")
                if result else
                PolicyDecision(Decision.DENY, "Denied by OPA policy (default-deny).")
            )
        if isinstance(result, dict):
            if result.get("require_approval"):
                return PolicyDecision(Decision.REQUIRE_APPROVAL,
                                      result.get("reason", "OPA policy requires human approval."))
            if result.get("allow"):
                return PolicyDecision(Decision.ALLOW, result.get("reason", "Allowed by OPA policy."))
            return PolicyDecision(Decision.DENY, result.get("reason", "Denied by OPA policy."))
        # No/opaque result -> default-deny.
        return PolicyDecision(Decision.DENY, "OPA returned no allow result (default-deny).")

    def _eval_cedar(self, req: ActionRequest, dlp: DLPResult | None) -> PolicyDecision:
        data = self._post(_decision_input(req, dlp))
        decision = str(data.get("decision", "Deny")).lower()
        if decision == "allow":
            return PolicyDecision(Decision.ALLOW, "Allowed by Cedar policy.")
        reasons = data.get("reasons") or data.get("errors") or []
        detail = f" ({'; '.join(map(str, reasons))})" if reasons else ""
        return PolicyDecision(Decision.DENY, f"Denied by Cedar policy.{detail}")


def get_external_engine() -> ExternalPolicyEngine | None:
    """Build the configured external engine, or None when using the built-in one."""
    settings = get_settings()
    kind = (settings.policy_engine or "").lower()
    if not kind:
        return None
    if not settings.policy_engine_url:
        _log.warning("policy_engine=%s but policy_engine_url is empty; using built-in engine", kind)
        return None
    return ExternalPolicyEngine(
        kind=kind,
        url=settings.policy_engine_url,
        fail_open=settings.policy_engine_fail_open,
        block_egress_on_secret=settings.dlp_block_egress_on_secret,
    )
