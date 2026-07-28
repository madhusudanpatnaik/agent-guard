"""Compliance evidence reporting — the assurance plane over the audit ledger.

Enforcement *does* governance; compliance reporting *proves* it to an auditor.
This module maps recognized control frameworks (SOC 2, GDPR, HIPAA, PCI-DSS) to
the concrete evidence AgentOps already records in its tamper-evident ledger, and
assembles an auditor-ready report for an org over a time window.

Two properties make the report trustworthy rather than marketing:

1. **Cryptographic attestation.** Every report embeds the result of a full
   hash-chain verification (valid / length / head hash). The evidence isn't just
   "here are some logs" — it's "here are logs that are provably un-tampered".
2. **Honest gaps.** A control whose evidence was never produced in the period is
   reported as a GAP ("control not exercised"), not silently passed. Auditors
   trust a report that admits gaps far more than one that claims 100%.

This maps AgentOps capabilities to control families; it is decision-support for
an audit, not a certification.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .audit.ledger import verify_chain
from .models import Alert, AuditRecord, Decision, Organization, PolicyVersion

# High-risk evidence threshold (mirrors the adaptive-risk step-up semantics).
_HIGH_RISK = 70


# --------------------------------------------------------------------------- #
# Control model + framework catalog
# --------------------------------------------------------------------------- #

@dataclass
class Control:
    id: str
    title: str
    requirement: str   # what the standard asks for
    how: str           # how AgentOps satisfies it
    evidence: str      # evidence-collector key (see _COLLECTORS)


FRAMEWORKS: dict[str, dict] = {
    "soc2": {
        "name": "SOC 2 (Trust Services Criteria)",
        "controls": [
            Control("CC6.1", "Logical access controls",
                    "Restrict logical access to information assets.",
                    "RBAC/ABAC policy engine gates every agent action (default-deny).",
                    "access_decisions"),
            Control("CC6.6", "Boundary / exfiltration protection",
                    "Protect against unauthorized data movement across boundaries.",
                    "DLP scans outbound payloads and blocks secret/PII exfiltration.",
                    "exfiltration_prevention"),
            Control("CC6.7", "Restrict data transmission",
                    "Restrict the transmission and movement of data to authorized users.",
                    "Credential vault: the plane holds upstream secrets; agents never do.",
                    "credential_isolation"),
            Control("CC7.2", "System monitoring",
                    "Monitor the system to detect anomalies and security events.",
                    "Risk scoring + anomaly detection + alert rules on every decision.",
                    "risk_monitoring"),
            Control("CC7.3", "Incident response",
                    "Respond to identified security incidents.",
                    "Alerts, auto-containment, and an org-wide emergency kill switch.",
                    "incident_response"),
            Control("CC8.1", "Change management",
                    "Authorize, design, and track changes to the system.",
                    "Policy versioning: every rule change is snapshotted and roll-backable.",
                    "change_management"),
            Control("A1.2", "Availability / resource limits",
                    "Manage capacity to meet availability commitments.",
                    "Per-agent quotas + rate limits guard against runaway loops.",
                    "rate_limiting"),
        ],
    },
    "gdpr": {
        "name": "GDPR (EU 2016/679)",
        "controls": [
            Control("Art.5(1)(c)", "Data minimisation",
                    "Process only data that is adequate and necessary.",
                    "DLP redacts PII/secrets from what agents and logs ever see.",
                    "dlp_redaction"),
            Control("Art.25", "Data protection by design and by default",
                    "Implement data-protection principles by design and default.",
                    "Zero-trust default-deny; least-privilege roles by default.",
                    "access_decisions"),
            Control("Art.30", "Records of processing activities",
                    "Maintain a record of processing activities.",
                    "Append-only, hash-chained audit ledger of every governed action.",
                    "audit_trail"),
            Control("Art.32", "Security of processing",
                    "Ensure a level of security appropriate to the risk.",
                    "Encryption at rest, access control, and continuous risk scoring.",
                    "risk_monitoring"),
        ],
    },
    "hipaa": {
        "name": "HIPAA Security Rule (45 CFR 164)",
        "controls": [
            Control("164.312(a)(1)", "Access control",
                    "Allow access only to those granted rights.",
                    "RBAC/ABAC restricts each agent to its authorized resources.",
                    "access_decisions"),
            Control("164.312(b)", "Audit controls",
                    "Record and examine activity in systems with ePHI.",
                    "Tamper-evident ledger records and verifies every decision.",
                    "audit_trail"),
            Control("164.312(e)(1)", "Transmission security",
                    "Guard against unauthorized access to ePHI in transit.",
                    "Credential vault + DLP on egress prevent ePHI leaving.",
                    "exfiltration_prevention"),
            Control("164.308(a)(1)(ii)(A)", "Risk analysis",
                    "Conduct an assessment of risks to ePHI.",
                    "Per-decision risk scoring with behavioral baselines.",
                    "risk_monitoring"),
        ],
    },
    "pci_dss": {
        "name": "PCI-DSS v4.0",
        "controls": [
            Control("Req.3", "Protect stored account data",
                    "Render cardholder data unreadable / minimize storage.",
                    "DLP detects PANs (Luhn-validated) and blocks/redacts them.",
                    "dlp_redaction"),
            Control("Req.7", "Restrict access by need to know",
                    "Limit access to system components and data.",
                    "RBAC/ABAC least-privilege enforcement on every action.",
                    "access_decisions"),
            Control("Req.8", "Identify users and authenticate access",
                    "Identify and authenticate access to system components.",
                    "Per-agent API-key identity; console SSO (OIDC) + SCIM.",
                    "credential_isolation"),
            Control("Req.10", "Log and monitor all access",
                    "Track and monitor all access to system components and data.",
                    "Hash-chained audit ledger + alerting on every decision.",
                    "audit_trail"),
        ],
    },
}


# --------------------------------------------------------------------------- #
# Evidence collectors — each returns count + a small sample from the ledger
# --------------------------------------------------------------------------- #

@dataclass
class Evidence:
    count: int
    sample: list[dict] = field(default_factory=list)
    note: str = ""
    by_design: bool = False  # satisfied structurally (no per-period evidence needed)


def _plural(n: int, singular: str, plural: str | None = None) -> str:
    """'1 action' / '2 actions' — an auditor-facing doc shouldn't read sloppily."""
    return f"{n} {singular if n == 1 else (plural or singular + 's')}"


def _ledger_count_sample(db: Session, org_id, since, until, *filters) -> Evidence:
    where = [AuditRecord.org_id == org_id,
             AuditRecord.created_at >= since, AuditRecord.created_at <= until, *filters]
    count = db.scalar(
        select(func.count(AuditRecord.id)).where(*where)) or 0
    rows = db.scalars(
        select(AuditRecord).where(*where).order_by(AuditRecord.seq.desc()).limit(3))
    sample = [
        {"seq": r.seq, "action_type": r.action_type, "resource": r.resource,
         "decision": r.decision, "reason": r.reason[:160],
         "created_at": r.created_at.isoformat() if r.created_at else None}
        for r in rows
    ]
    return Evidence(count=count, sample=sample)


def _c_access_decisions(db, org_id, since, until) -> Evidence:
    ev = _ledger_count_sample(db, org_id, since, until, AuditRecord.billable.is_(True))
    denied = db.scalar(select(func.count(AuditRecord.id)).where(
        AuditRecord.org_id == org_id, AuditRecord.created_at >= since,
        AuditRecord.created_at <= until, AuditRecord.billable.is_(True),
        AuditRecord.decision == Decision.DENY)) or 0
    ev.note = (f"{_plural(ev.count, 'governed decision')}, {denied} denied "
               "(least privilege enforced)")
    return ev


def _c_exfiltration_prevention(db, org_id, since, until) -> Evidence:
    ev = _ledger_count_sample(db, org_id, since, until,
                              AuditRecord.decision == Decision.DENY,
                              AuditRecord.reason.like("Data-exfiltration%"))
    ev.note = (f"{_plural(ev.count, 'outbound action')} blocked for "
               "carrying secrets/PII")
    return ev


def _c_dlp_redaction(db, org_id, since, until) -> Evidence:
    ev = _ledger_count_sample(db, org_id, since, until, AuditRecord.dlp_count > 0)
    ev.note = (f"{_plural(ev.count, 'action')} had sensitive data "
               "detected and redacted")
    return ev


def _c_risk_monitoring(db, org_id, since, until) -> Evidence:
    high = db.scalar(select(func.count(AuditRecord.id)).where(
        AuditRecord.org_id == org_id, AuditRecord.created_at >= since,
        AuditRecord.created_at <= until, AuditRecord.risk_score >= _HIGH_RISK)) or 0
    ev = _ledger_count_sample(db, org_id, since, until, AuditRecord.risk_score > 0)
    ev.note = (f"{_plural(ev.count, 'action')} risk-scored; {high} flagged "
               f"high-risk (score ≥ {_HIGH_RISK})")
    return ev


def _c_incident_response(db, org_id, since, until) -> Evidence:
    alerts = db.scalar(select(func.count(Alert.id)).where(
        Alert.org_id == org_id, Alert.created_at >= since, Alert.created_at <= until)) or 0
    contain = db.scalar(select(func.count(AuditRecord.id)).where(
        AuditRecord.org_id == org_id, AuditRecord.created_at >= since,
        AuditRecord.created_at <= until,
        AuditRecord.action_type.in_(["org.contain", "org.resume"]))) or 0
    ev = _ledger_count_sample(db, org_id, since, until,
                              AuditRecord.action_type.in_(["org.contain", "org.resume"]))
    ev.count = alerts + contain
    ev.note = (f"{_plural(alerts, 'alert')} raised, "
               f"{_plural(contain, 'containment action')}")
    return ev


def _c_change_management(db, org_id, since, until) -> Evidence:
    count = db.scalar(select(func.count(PolicyVersion.id)).where(
        PolicyVersion.org_id == org_id, PolicyVersion.created_at >= since,
        PolicyVersion.created_at <= until)) or 0
    rows = db.scalars(select(PolicyVersion).where(
        PolicyVersion.org_id == org_id, PolicyVersion.created_at >= since,
        PolicyVersion.created_at <= until).order_by(PolicyVersion.created_at.desc()).limit(3))
    sample = [{"policy_id": r.policy_id, "version": r.version, "action": r.action,
               "changed_by": r.changed_by,
               "created_at": r.created_at.isoformat() if r.created_at else None} for r in rows]
    return Evidence(count=count, sample=sample,
                    note=f"{_plural(count, 'policy change')} recorded "
                         "(versioned + roll-backable)")


def _c_rate_limiting(db, org_id, since, until) -> Evidence:
    # Denials attributable to quota/rate ceilings.
    where = [AuditRecord.org_id == org_id, AuditRecord.created_at >= since,
             AuditRecord.created_at <= until, AuditRecord.decision == Decision.DENY]
    count = db.scalar(select(func.count(AuditRecord.id)).where(
        *where, AuditRecord.reason.like("%quota%"))) or 0
    count += db.scalar(select(func.count(AuditRecord.id)).where(
        *where, AuditRecord.reason.like("Rate limit%"))) or 0
    return Evidence(count=count, by_design=True,
                    note=("Per-agent quotas + rate limits configured; "
                          f"{_plural(count, 'action')} throttled"))


def _c_credential_isolation(db, org_id, since, until) -> Evidence:
    # Structural control: agents never hold upstream credentials (vaulted).
    return Evidence(count=0, by_design=True,
                    note="Upstream credentials are vault-encrypted and injected by the plane; "
                         "agents authenticate with scoped API keys and never receive secrets.")


def _c_audit_trail(db, org_id, since, until) -> Evidence:
    ev = _ledger_count_sample(db, org_id, since, until)
    ev.note = (f"{_plural(ev.count, 'immutable, hash-chained record')} "
               "in the reporting period")
    return ev


_COLLECTORS = {
    "access_decisions": _c_access_decisions,
    "exfiltration_prevention": _c_exfiltration_prevention,
    "dlp_redaction": _c_dlp_redaction,
    "risk_monitoring": _c_risk_monitoring,
    "incident_response": _c_incident_response,
    "change_management": _c_change_management,
    "rate_limiting": _c_rate_limiting,
    "credential_isolation": _c_credential_isolation,
    "audit_trail": _c_audit_trail,
}


# --------------------------------------------------------------------------- #
# Report assembly
# --------------------------------------------------------------------------- #

def _classify(evidence: Evidence) -> str:
    """Status of a control for the period.

    * ``satisfied``   — evidence was produced (or the control holds by design).
    * ``not_exercised`` — the capability exists but produced no evidence in the
      window; an honest gap for the auditor to note, not a pass.
    """
    if evidence.by_design or evidence.count > 0:
        return "satisfied"
    return "not_exercised"


def build_report(db: Session, org: Organization, framework: str,
                 since: datetime, until: datetime) -> dict:
    fw = FRAMEWORKS.get(framework)
    if fw is None:
        raise ValueError(f"unknown framework '{framework}' "
                         f"(supported: {', '.join(FRAMEWORKS)})")

    # Cryptographic attestation: prove the evidence itself is un-tampered.
    chain = verify_chain(db)

    controls_out = []
    satisfied = 0
    gaps = []
    for control in fw["controls"]:
        collector = _COLLECTORS[control.evidence]
        evidence = collector(db, org.id, since, until)
        statusv = _classify(evidence)
        if statusv == "satisfied":
            satisfied += 1
        else:
            gaps.append(control.id)
        controls_out.append({
            "id": control.id, "title": control.title,
            "requirement": control.requirement, "agentops_control": control.how,
            "status": statusv, "evidence_count": evidence.count,
            "evidence_note": evidence.note, "sample": evidence.sample,
        })

    total = len(fw["controls"])
    return {
        "framework": framework,
        "framework_name": fw["name"],
        "organization": org.name,
        "org_slug": org.slug,
        "period_start": since.isoformat(),
        "period_end": until.isoformat(),
        "ledger_attestation": {
            "chain_valid": chain.valid,
            "records": chain.length,
            "head_hash": chain.head_hash,
            "detail": chain.detail,
            "statement": ("The audit ledger backing this report is a keyed-HMAC "
                          "hash chain; a full re-verification confirms it is intact."
                          if chain.valid else
                          "WARNING: ledger integrity verification FAILED — evidence "
                          "in this report cannot be trusted until resolved."),
        },
        "coverage": {"controls_total": total, "controls_satisfied": satisfied,
                     "controls_not_exercised": total - satisfied,
                     "coverage_pct": round(100 * satisfied / total) if total else 0},
        "gaps": gaps,
        "controls": controls_out,
        "disclaimer": ("This report maps AgentOps enforcement capabilities to control "
                       "families and presents evidence from the audit ledger. It is "
                       "decision-support for an audit, not a certification of compliance."),
    }


def default_window() -> tuple[datetime, datetime]:
    """Default reporting window: the trailing 90 days."""
    now = datetime.now(timezone.utc)
    return now - timedelta(days=90), now


def render_markdown(report: dict) -> str:
    """Render a report as a human-readable Markdown document (auditor-friendly)."""
    a = report["ledger_attestation"]
    cov = report["coverage"]
    lines = [
        f"# Compliance Evidence Report — {report['framework_name']}",
        "",
        f"**Organization:** {report['organization']}  ",
        f"**Period:** {report['period_start']} → {report['period_end']}  ",
        f"**Control coverage:** {cov['controls_satisfied']}/{cov['controls_total']} "
        f"({cov['coverage_pct']}%)",
        "",
        "## Ledger integrity attestation",
        "",
        f"- **Chain valid:** {'✅ yes' if a['chain_valid'] else '❌ NO'}",
        f"- **Records:** {a['records']}",
        f"- **Head hash:** `{a['head_hash']}`",
        f"- {a['statement']}",
        "",
        "## Controls",
        "",
    ]
    for c in report["controls"]:
        badge = "✅ satisfied" if c["status"] == "satisfied" else "⚠️ not exercised in period"
        lines += [
            f"### {c['id']} — {c['title']}  ({badge})",
            "",
            f"- **Requirement:** {c['requirement']}",
            f"- **AgentOps control:** {c['agentops_control']}",
            f"- **Evidence:** {c['evidence_note']}",
            "",
        ]
    if report["gaps"]:
        lines += ["## Gaps (controls not exercised in the period)", "",
                  ", ".join(report["gaps"]),
                  "", "_These capabilities are configured but produced no evidence in the "
                  "reporting window. Confirm this matches expected activity._", ""]
    lines += ["---", "", f"_{report['disclaimer']}_", ""]
    return "\n".join(lines)
