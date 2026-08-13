"""Policy intelligence — static + data-driven analysis of a role's policies.

As policy sets grow, they accumulate rules that are redundant, unreachable, or
dangerously broad — and gaps that show up as repeated denials in the ledger.
This analyzer inspects a role's policies (pure logic) and cross-references the
audit history (data-driven) to surface:

* **shadowed allow** — an allow that a deny always overrides, so it never grants
  (deny-overrides-allow means the allow is dead weight or a misunderstanding);
* **redundant** — duplicate policies with identical effect/resource/actions;
* **overly broad** — allow-everything rules (``**`` resource + ``*`` actions)
  that violate least privilege;
* **unused** — policies that have never matched a real decision in the ledger;
* **denial hotspots** — resources/actions this role's agents are repeatedly
  denied, i.e. candidate gaps to review.

Findings are advisory (nothing is changed); an operator reviews and acts.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..dlp.scanner import DLPFinding, DLPResult
from ..models import AuditRecord, Decision, Effect, Policy, Role
from ..utils import resource_family
from .engine import ActionRequest, PolicyEngine, glob_match


@dataclass
class PolicyFinding:
    kind: str
    severity: str  # "warning" | "info"
    message: str
    policy_ids: list[int] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"kind": self.kind, "severity": self.severity,
                "message": self.message, "policy_ids": self.policy_ids}


def _actions_overlap(a: Policy, b: Policy) -> bool:
    aa = [x.lower() for x in (a.actions or [])]
    bb = [x.lower() for x in (b.actions or [])]
    if any(x in ("*", "**") for x in aa) or any(x in ("*", "**") for x in bb):
        return True
    aset, bset = set(aa), set(bb)
    if aset & bset:
        return True
    # Glob overlap (e.g. "http.*" vs "http.post").
    return any(glob_match(p, q) or glob_match(q, p) for p in aa for q in bb)


def _resource_covers(deny_resource: str, allow_resource: str) -> bool:
    """Heuristic: does the deny pattern match everything the allow pattern does?

    Exact-equal, deny is a catch-all (``**``/``*``), or the deny glob matches the
    allow's resource literal. Conservative — only flags clear shadowing.
    """
    if deny_resource in ("**", "*"):
        return True
    if deny_resource == allow_resource:
        return True
    return glob_match(deny_resource, allow_resource)


def _is_broad(p: Policy) -> bool:
    return (p.resource in ("**", "*")
            and any(x in ("*", "**") for x in (p.actions or [])))


@dataclass
class PolicyAnalysis:
    role_id: int
    role_name: str
    findings: list[PolicyFinding] = field(default_factory=list)
    unused_policy_ids: list[int] = field(default_factory=list)
    denial_hotspots: list[dict] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "role_id": self.role_id,
            "role_name": self.role_name,
            "findings": [f.as_dict() for f in self.findings],
            "unused_policy_ids": self.unused_policy_ids,
            "denial_hotspots": self.denial_hotspots,
        }


def analyze_role(db: Session, role: Role) -> PolicyAnalysis:
    policies = [p for p in role.policies if p.enabled]
    analysis = PolicyAnalysis(role_id=role.id, role_name=role.name)
    allows = [p for p in policies if p.effect == Effect.ALLOW]
    denies = [p for p in policies if p.effect == Effect.DENY]

    # 1. Shadowed allows (a deny always overrides them).
    for a in allows:
        shadowing = [d for d in denies
                     if _resource_covers(d.resource, a.resource) and _actions_overlap(d, a)]
        if shadowing:
            analysis.findings.append(PolicyFinding(
                kind="shadowed_allow", severity="warning",
                message=(f"Allow '{a.name or a.resource}' is shadowed by deny "
                         f"policies {[d.id for d in shadowing]} (deny overrides allow) — "
                         "it can never grant access."),
                policy_ids=[a.id] + [d.id for d in shadowing],
            ))

    # 2. Redundant / duplicate policies.
    seen: dict[tuple, int] = {}
    for p in policies:
        sig = (p.effect, p.resource.lower(),
               tuple(sorted(x.lower() for x in (p.actions or []))))
        if sig in seen:
            analysis.findings.append(PolicyFinding(
                kind="redundant", severity="info",
                message=(f"Policy '{p.name or p.resource}' duplicates policy #{seen[sig]} "
                         "(same effect, resource, actions)."),
                policy_ids=[seen[sig], p.id],
            ))
        else:
            seen[sig] = p.id

    # 3. Overly broad allow (least-privilege violation).
    for p in allows:
        if _is_broad(p):
            analysis.findings.append(PolicyFinding(
                kind="overly_broad", severity="warning",
                message=(f"Allow '{p.name or p.resource}' grants '*' actions on '{p.resource}' "
                         "— violates least privilege; scope it to specific resources/actions."),
                policy_ids=[p.id],
            ))

    # 4. Unused policies — never matched a real decision in the ledger.
    # Role names are unique only per org, so every ledger query MUST also scope
    # by org_id or it would mix another tenant's audit rows (cross-tenant leak).
    matched = set(db.scalars(
        select(AuditRecord.matched_policy_id)
        .where(AuditRecord.matched_policy_id.isnot(None),
               AuditRecord.role_name == role.name,
               AuditRecord.org_id == role.org_id)
        .distinct()
    ))
    total_for_role = db.scalar(
        select(func.count(AuditRecord.id)).where(
            AuditRecord.role_name == role.name, AuditRecord.org_id == role.org_id)
    ) or 0
    if total_for_role > 0:  # only meaningful once the role has traffic
        analysis.unused_policy_ids = [p.id for p in policies if p.id not in matched]

    # 5. Denial hotspots — most-denied (resource, action) for this role.
    rows = db.execute(
        select(AuditRecord.resource, AuditRecord.action_type,
               func.count(AuditRecord.id).label("n"))
        .where(AuditRecord.role_name == role.name,
               AuditRecord.org_id == role.org_id,
               AuditRecord.decision == Decision.DENY,
               AuditRecord.billable.is_(True))
        .group_by(AuditRecord.resource, AuditRecord.action_type)
        .order_by(func.count(AuditRecord.id).desc())
        .limit(5)
    ).all()
    analysis.denial_hotspots = [
        {"resource": r.resource, "action_type": r.action_type, "denials": r.n} for r in rows
    ]
    return analysis


# --------------------------------------------------------------------------- #
# Policy recommendations — turn recurring default-deny gaps into candidate rules
# --------------------------------------------------------------------------- #

def _generalize(resource: str) -> str:
    """Collapse a per-id resource to its family (shared with novelty scoring)."""
    return resource_family(resource)


@dataclass
class PolicyRecommendation:
    resource: str
    actions: list[str]
    denials: int
    confidence: str          # "high" | "medium" | "low"
    rationale: str

    def as_dict(self) -> dict:
        return {"resource": self.resource, "actions": self.actions,
                "denials": self.denials, "confidence": self.confidence,
                "rationale": self.rationale}


def _confidence(denials: int, distinct_targets: int) -> str:
    # More denials AND more distinct concrete targets => stronger signal that this
    # is a real, recurring access need rather than a one-off probe.
    if denials >= 5 and distinct_targets >= 2:
        return "high"
    if denials >= 3:
        return "medium"
    return "low"


def recommend_policies(db: Session, role: Role, *, min_denials: int = 2,
                       limit: int = 10) -> list[PolicyRecommendation]:
    """Suggest allow policies for recurring **default-deny** gaps.

    Only default-deny denials are considered — those mean "no policy grants this",
    i.e. a genuine coverage gap. Denials from an explicit deny policy, a DLP
    exfiltration block, quota, or containment are *intentional* and never
    recommended away. Per-id resources are generalized so many denials on
    ``db:customers:<id>`` become one ``db:customers:*`` suggestion, and an
    existing matching allow suppresses the recommendation.
    """
    existing_allow = [p for p in role.policies
                      if p.enabled and p.effect == Effect.ALLOW]

    rows = db.execute(
        select(AuditRecord.resource, AuditRecord.action_type,
               func.count(AuditRecord.id).label("n"))
        .where(AuditRecord.role_name == role.name,
               AuditRecord.org_id == role.org_id,
               AuditRecord.decision == Decision.DENY,
               AuditRecord.billable.is_(True),
               AuditRecord.reason.like("Default-deny%"))
        .group_by(AuditRecord.resource, AuditRecord.action_type)
    ).all()

    # Collapse per-id resources; track distinct concrete targets + total denials.
    agg: dict[tuple[str, str], dict] = {}
    for r in rows:
        gen = _generalize(r.resource)
        key = (gen, r.action_type)
        entry = agg.setdefault(key, {"denials": 0, "targets": set()})
        entry["denials"] += r.n
        entry["targets"].add(r.resource)

    # Merge actions that share a generalized resource into one recommendation.
    by_resource: dict[str, dict] = {}
    for (gen, action), info in agg.items():
        if info["denials"] < min_denials:
            continue
        # Skip if an existing allow already covers this resource+action.
        if any(glob_match(p.resource, gen) and _action_covers(p, action)
               for p in existing_allow):
            continue
        slot = by_resource.setdefault(gen, {"actions": set(), "denials": 0, "targets": set()})
        slot["actions"].add(action)
        slot["denials"] += info["denials"]
        slot["targets"] |= info["targets"]

    recs = []
    for gen, slot in by_resource.items():
        actions = sorted(slot["actions"])
        recs.append(PolicyRecommendation(
            resource=gen,
            actions=actions,
            denials=slot["denials"],
            confidence=_confidence(slot["denials"], len(slot["targets"])),
            rationale=(f"{slot['denials']} default-deny denial(s) across "
                       f"{len(slot['targets'])} target(s) for {', '.join(actions)} "
                       f"on '{gen}' — no policy currently grants it."),
        ))
    recs.sort(key=lambda r: r.denials, reverse=True)
    return recs[:limit]


def _action_covers(policy: Policy, action_type: str) -> bool:
    acts = [a.lower() for a in (policy.actions or [])]
    if any(a in ("*", "**") for a in acts):
        return True
    return any(glob_match(a, action_type) for a in acts)


# --------------------------------------------------------------------------- #
# Impact preview — replay a candidate policy against real denied traffic
# --------------------------------------------------------------------------- #

def _rebuild_dlp(findings: list | None) -> DLPResult:
    """Reconstruct a DLPResult from stored finding dicts.

    The raw payload isn't retained, but the DLP findings are — enough to preserve
    the engine's exfiltration-guard behavior during a dry-run (a candidate allow
    must not appear to "newly permit" something DLP would still block on egress).
    """
    objs = [
        DLPFinding(detector=f.get("detector", ""), severity=f.get("severity", "low"),
                   count=int(f.get("count", 1)), sample=f.get("sample", ""),
                   path=f.get("path", ""))
        for f in (findings or [])
    ]
    return DLPResult(findings=objs, redacted=None)


@dataclass
class PolicyImpact:
    resource: str
    actions: list[str]
    would_allow: int          # previously-denied actions this policy would now permit
    sensitive_allow: int      # …of which carried DLP findings (secrets/PII)
    sample: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"resource": self.resource, "actions": self.actions,
                "would_allow": self.would_allow, "sensitive_allow": self.sensitive_allow,
                "sample": self.sample, "warnings": self.warnings}


def preview_policy(db: Session, role: Role, resource: str, actions: list[str],
                   *, lookback: int = 1000, sample_size: int = 10) -> PolicyImpact:
    """Dry-run a candidate allow policy against the role's recent denied traffic.

    Replays each recent DENY for the role through the policy engine with, and
    without, the candidate rule added to the role's live policy set — and reports
    what would *flip* from denied to allowed. Anything that would be newly
    allowed **and** carried DLP findings (or is an egress action) is flagged so
    an operator sees the blast radius before adopting the rule. Nothing is
    written; this is pure evaluation.
    """
    settings = get_settings()
    engine = PolicyEngine(default_deny=settings.default_deny,
                          block_egress_on_secret=settings.dlp_block_egress_on_secret)
    candidate = Policy(id=-1, role_id=role.id, name="candidate", effect=Effect.ALLOW,
                       resource=resource, actions=list(actions or ["*"]),
                       conditions={}, priority=0, enabled=True)
    current = [p for p in role.policies if p.enabled]
    with_candidate = current + [candidate]

    recent = list(db.scalars(
        select(AuditRecord)
        .where(AuditRecord.role_name == role.name,
               AuditRecord.org_id == role.org_id,
               AuditRecord.decision == Decision.DENY,
               AuditRecord.billable.is_(True))
        .order_by(AuditRecord.seq.desc())
        .limit(lookback)
    ))

    impact = PolicyImpact(resource=resource, actions=list(actions or ["*"]),
                          would_allow=0, sensitive_allow=0)
    seen_keys: set[tuple[str, str]] = set()
    for rec in recent:
        key = (rec.action_type, rec.resource)
        if key in seen_keys:
            continue
        seen_keys.add(key)
        dlp = _rebuild_dlp(rec.dlp_findings)
        req = ActionRequest(rec.action_type, rec.resource)
        before = engine.evaluate(req, current, dlp=dlp).decision
        after = engine.evaluate(req, with_candidate, dlp=dlp).decision
        if before != Decision.ALLOW and after == Decision.ALLOW:
            impact.would_allow += 1
            sensitive = (rec.dlp_count or 0) > 0 or req.is_egress()
            if rec.dlp_count and rec.dlp_count > 0:
                impact.sensitive_allow += 1
            if len(impact.sample) < sample_size:
                impact.sample.append({
                    "action_type": rec.action_type, "resource": rec.resource,
                    "sensitive": bool(sensitive), "dlp_count": rec.dlp_count or 0,
                })

    if _is_broad(candidate):
        impact.warnings.append("Candidate is allow-everything (**/*) — violates least privilege.")
    if impact.sensitive_allow:
        impact.warnings.append(
            f"{impact.sensitive_allow} newly-allowed action(s) previously carried DLP "
            "findings (secrets/PII) — review before adopting.")
    if impact.would_allow == 0:
        impact.warnings.append(
            "No recent denied traffic would be affected — the rule may be unnecessary "
            "or the gap predates the retained ledger window.")
    return impact
