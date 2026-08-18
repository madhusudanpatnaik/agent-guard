"""Policy Decision Point (PDP).

The engine takes an :class:`ActionRequest` from an agent and, given the agent's
role policies plus a DLP scan of the payload, returns a single
:class:`PolicyDecision` of ``allow`` / ``deny`` / ``require_approval``.

Precedence (highest wins)::

    1. explicit matching DENY policy            -> deny
    2. DLP exfiltration block on egress          -> deny
    3. constraint violation (amount/time/rate)   -> deny
    4. approval obligation (flag or threshold)   -> require_approval
    5. matching ALLOW policy                     -> allow
    6. no matching policy                        -> deny (default-deny) / allow

The engine is a pure function of its inputs (plus an optional rate-count
callback), which makes it trivially unit-testable and deterministic.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, time, timezone
from typing import Any

from ..dlp.scanner import DLPResult, scan_payload
from ..models import Decision, Effect, Policy

# Schemes / verbs that move data outside the trust boundary. Kept deliberately
# broad: for an exfiltration guard, over-classifying an action as egress fails
# safe (it only tightens the DLP check), whereas missing one fails open.
_EGRESS_SCHEMES = (
    "http", "https", "email", "smtp", "webhook", "external", "ftp", "sftp", "ftps",
    "s3", "gs", "gcs", "azure", "blob", "dns", "file", "tcp", "udp", "slack",
    "telegram", "discord", "pastebin", "mailto", "url",
)
_EGRESS_VERB_HINTS = (
    "send", "post", "put", "email", "upload", "exfil", "publish", "webhook",
    "share", "sync", "export", "transmit", "leak", "transfer", "notify", "push",
)


@dataclass
class ActionRequest:
    action_type: str
    resource: str
    payload: Any = None
    metadata: dict[str, Any] = field(default_factory=dict)
    # ABAC context: attributes about the subject / resource / environment, e.g.
    #   {"subject": {"role": "billing", "clearance": 3},
    #    "resource": {"tier": "vip"}, "env": {"ip": "10.0.0.4", "mfa": true}}
    # Policies may constrain on these via conditions["attributes"].
    attributes: dict[str, Any] = field(default_factory=dict)

    def is_egress(self) -> bool:
        scheme = self.resource.split(":", 1)[0].lower() if ":" in self.resource else ""
        if scheme in _EGRESS_SCHEMES:
            return True
        verb = self.action_type.lower()
        return any(h in verb for h in _EGRESS_VERB_HINTS)


@dataclass
class PolicyDecision:
    decision: str
    reason: str
    matched_policy_id: int | None = None
    obligations: list[str] = field(default_factory=list)
    dlp: DLPResult | None = None

    @property
    def allowed(self) -> bool:
        return self.decision == Decision.ALLOW


# --------------------------------------------------------------------------- #
# Glob matching
# --------------------------------------------------------------------------- #

_GLOB_CACHE: dict[str, re.Pattern] = {}


def _compile_glob(pattern: str) -> re.Pattern:
    cached = _GLOB_CACHE.get(pattern)
    if cached:
        return cached
    out = ["^"]
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "*":
            if i + 1 < len(pattern) and pattern[i + 1] == "*":
                out.append(".*")  # ** crosses segment separators
                i += 2
                continue
            out.append("[^:/]*")  # * stays within a segment
        elif ch == "?":
            out.append(".")
        else:
            out.append(re.escape(ch))
        i += 1
    out.append("$")
    compiled = re.compile("".join(out))
    _GLOB_CACHE[pattern] = compiled
    return compiled


def glob_match(pattern: str, value: str) -> bool:
    """Case-insensitive glob match. ``*`` within a segment, ``**`` across."""
    return bool(_compile_glob(pattern.lower()).match(value.lower()))


def _action_matches(policy_actions: list[str], action_type: str) -> bool:
    if not policy_actions:
        return False
    for pat in policy_actions:
        if pat == "*" or pat == "**":
            return True
        if glob_match(pat, action_type):
            return True
    return False


# --------------------------------------------------------------------------- #
# ABAC — attribute-based access control
# --------------------------------------------------------------------------- #

def _lookup_attr(context: dict[str, Any], dotted: str) -> Any:
    """Resolve a dotted path (``subject.role``) into the attribute context."""
    node: Any = context
    for part in dotted.split("."):
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return None
    return node


def _match_one(actual: Any, matcher: Any) -> bool:
    """Match a single attribute value against a matcher.

    Matcher forms:
      * scalar        -> equality
      * list          -> membership (``actual in matcher``)
      * {"op": ...}   -> eq|ne|in|nin|gt|gte|lt|lte|glob|regex|exists
    """
    if isinstance(matcher, dict) and "op" in matcher:
        op = matcher["op"]
        want = matcher.get("value")
        if op == "exists":
            return (actual is not None) == bool(want)
        if op == "eq":
            return actual == want
        if op == "ne":
            return actual != want
        if op == "in":
            return actual in (want or [])
        if op == "nin":
            return actual not in (want or [])
        if op == "glob":
            return actual is not None and glob_match(str(want), str(actual))
        if op == "regex":
            if actual is None or want is None:
                return False
            try:
                return re.search(str(want), str(actual)) is not None
            except re.error:
                return False  # a malformed pattern never matches (fail closed)
        if op in {"gt", "gte", "lt", "lte"}:
            a = _coerce_number(actual)
            b = _coerce_number(want)
            if a is None or b is None:
                return False
            return {"gt": a > b, "gte": a >= b, "lt": a < b, "lte": a <= b}[op]
        return False
    if isinstance(matcher, list):
        return actual in matcher
    return actual == matcher


def _attributes_match(conditions: dict[str, Any], request: "ActionRequest") -> bool:
    """True unless an ``attributes`` block is present and any predicate fails.

    A policy whose attribute predicates are not all satisfied simply does not
    apply (it is filtered out of the match set) — standard ABAC semantics, so an
    unsatisfied allow falls through to default-deny rather than granting.
    """
    attrs = conditions.get("attributes")
    if not attrs:
        return True
    for path, matcher in attrs.items():
        if not _match_one(_lookup_attr(request.attributes, path), matcher):
            return False
    return True


# --------------------------------------------------------------------------- #
# Engine
# --------------------------------------------------------------------------- #

class PolicyEngine:
    def __init__(self, *, default_deny: bool = True, block_egress_on_secret: bool = True):
        self.default_deny = default_deny
        self.block_egress_on_secret = block_egress_on_secret

    def evaluate(
        self,
        request: ActionRequest,
        policies: list[Policy],
        *,
        now: datetime | None = None,
        rate_counter: Callable[[int], int] | None = None,
        dlp: DLPResult | None = None,
    ) -> PolicyDecision:
        now = now or datetime.now(timezone.utc)
        dlp = dlp if dlp is not None else scan_payload(request.payload)
        obligations: list[str] = []
        if dlp.has_findings:
            obligations.append("redact_payload")

        matching = [
            p
            for p in policies
            if p.enabled
            and glob_match(p.resource, request.resource)
            and _action_matches(list(p.actions or []), request.action_type)
            and _attributes_match(p.conditions or {}, request)
        ]
        matching.sort(key=lambda p: p.priority, reverse=True)

        deny = next((p for p in matching if p.effect == Effect.DENY), None)
        if deny:
            return PolicyDecision(
                Decision.DENY,
                f"Blocked by deny policy #{deny.id} ({deny.name or deny.resource}).",
                matched_policy_id=deny.id,
                obligations=obligations,
                dlp=dlp,
            )

        # 2. Exfiltration guard — applies even without a matching allow.
        if self.block_egress_on_secret and request.is_egress() and dlp.blocking:
            leaked = ", ".join(sorted({f.detector for f in dlp.findings}))
            return PolicyDecision(
                Decision.DENY,
                f"Data-exfiltration prevented: sensitive data ({leaked}) "
                f"in an outbound '{request.action_type}' to {request.resource}.",
                obligations=obligations,
                dlp=dlp,
            )

        allow = next((p for p in matching if p.effect == Effect.ALLOW), None)
        if not allow:
            if self.default_deny:
                return PolicyDecision(
                    Decision.DENY,
                    f"Default-deny: no policy grants '{request.action_type}' "
                    f"on '{request.resource}' for this role.",
                    obligations=obligations,
                    dlp=dlp,
                )
            return PolicyDecision(
                Decision.ALLOW,
                "Permitted by permissive default (default-deny disabled).",
                obligations=obligations,
                dlp=dlp,
            )

        # 3/4. Constraint evaluation on the winning allow policy.
        verdict = self._check_constraints(allow, request, now=now, rate_counter=rate_counter)
        if verdict is not None:
            decision, reason = verdict
            return PolicyDecision(
                decision,
                reason,
                matched_policy_id=allow.id,
                obligations=obligations,
                dlp=dlp,
            )

        if allow.require_approval:
            return PolicyDecision(
                Decision.REQUIRE_APPROVAL,
                f"Policy #{allow.id} requires human approval for this action.",
                matched_policy_id=allow.id,
                obligations=obligations,
                dlp=dlp,
            )

        return PolicyDecision(
            Decision.ALLOW,
            f"Allowed by policy #{allow.id} ({allow.name or allow.resource}).",
            matched_policy_id=allow.id,
            obligations=obligations,
            dlp=dlp,
        )

    # -- constraints ------------------------------------------------------
    def _check_constraints(
        self,
        policy: Policy,
        request: ActionRequest,
        *,
        now: datetime,
        rate_counter: Callable[[int], int] | None,
    ) -> tuple[str, str] | None:
        cond = policy.conditions or {}

        # Monetary ceiling.
        amount = _coerce_number(request.metadata.get("amount"))
        amount_constrained = "max_amount" in cond or "require_approval_over" in cond

        # Fail closed: a policy that constrains amount must not be bypassable by
        # simply omitting (or malforming) the amount. Route such actions to a human.
        if amount_constrained and amount is None:
            return (
                Decision.REQUIRE_APPROVAL,
                "Amount-constrained action submitted without a verifiable numeric "
                "amount — routed to human review.",
            )

        # A NEGATIVE amount is malformed for this purpose too, and used to sail
        # straight through: both bounds below are `amount > limit`, so -9500
        # cleared a max_amount of 5000 AND a require_approval_over of 500 with
        # no ceiling and no human, while +9500 was correctly denied. Some
        # payment APIs also treat a negative refund as a charge, which turns
        # the bypass into a transfer in the opposite direction. There is no
        # legitimate negative value for a spend ceiling to bound, so this takes
        # the same route the comment above already prescribes for a malformed
        # amount rather than inventing sign semantics (e.g. silently comparing
        # abs(), which would reinterpret the caller's intent).
        if amount_constrained and amount is not None and amount < 0:
            return (
                Decision.REQUIRE_APPROVAL,
                f"Amount-constrained action submitted with a negative amount "
                f"({amount:g}) — cannot be bounded by a spending limit, routed "
                "to human review.",
            )

        # All operator-supplied numeric conditions are parsed with the fail-safe
        # coercer and fail CLOSED on a malformed value — a bad condition must
        # never raise on the authorize hot path (that would 500 the decision and
        # skip the audit record), matching how the time-window check fails closed.
        if "max_amount" in cond and amount is not None:
            ceiling = _coerce_number(cond["max_amount"])
            if ceiling is None:
                return (
                    Decision.REQUIRE_APPROVAL,
                    "Policy max_amount is not a valid number — routed to human review.",
                )
            if amount > ceiling:
                return (
                    Decision.DENY,
                    f"Amount {amount} exceeds policy max_amount {cond['max_amount']}.",
                )

        # Time-of-day window (UTC), e.g. {"start": "09:00", "end": "17:00"}.
        window = cond.get("time_window")
        if window and not _within_window(now, window):
            return (
                Decision.DENY,
                f"Outside permitted time window {window.get('start')}–{window.get('end')} UTC.",
            )

        # Rate limit, e.g. {"count": 5, "per_seconds": 60}.
        rl = cond.get("rate_limit")
        if rl and rate_counter is not None:
            per_seconds = _coerce_number(rl.get("per_seconds", 60))
            count = _coerce_number(rl.get("count", 0))
            if per_seconds is None or count is None:
                return (
                    Decision.DENY,
                    "Policy rate_limit has a non-numeric value — denied (fail-closed).",
                )
            recent = rate_counter(int(per_seconds))
            if recent >= int(count):
                return (
                    Decision.DENY,
                    f"Rate limit exceeded: {recent} actions in the last "
                    f"{rl.get('per_seconds', 60)}s (max {rl.get('count')}).",
                )

        # Approval threshold on amount.
        if "require_approval_over" in cond and amount is not None:
            threshold = _coerce_number(cond["require_approval_over"])
            if threshold is None:
                return (
                    Decision.REQUIRE_APPROVAL,
                    "Policy require_approval_over is not a valid number — routed to human review.",
                )
            if amount > threshold:
                return (
                    Decision.REQUIRE_APPROVAL,
                    f"Amount {amount} exceeds approval threshold "
                    f"{cond['require_approval_over']} — human sign-off required.",
                )
        return None


def _coerce_number(value: Any) -> float | None:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.replace(",", "").strip())
        except ValueError:
            return None
    return None


def _within_window(now: datetime, window: dict[str, str]) -> bool:
    try:
        start = _parse_hhmm(window["start"])
        end = _parse_hhmm(window["end"])
    except (KeyError, ValueError, TypeError):
        return False  # fail closed: a malformed window denies rather than allows
    current = now.timetz().replace(tzinfo=None)
    current_t = time(current.hour, current.minute)
    if start <= end:
        return start <= current_t <= end
    # Overnight window (e.g. 22:00–06:00).
    return current_t >= start or current_t <= end


def _parse_hhmm(value: str) -> time:
    hh, mm = value.split(":")
    return time(int(hh), int(mm))
