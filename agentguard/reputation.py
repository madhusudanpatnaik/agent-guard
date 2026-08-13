"""Agent reputation — a rolling trust score from an agent's own behavior.

Not every risky agent trips a hard rule; some erode trust gradually — a rising
denial rate, occasional DLP hits, the odd exfiltration attempt. Reputation folds
that history into a single 0–100 score (100 = spotless) so operators can triage
which agents to review or tighten, and so automation can gate on trust.

The score starts at 100 and subtracts penalties derived entirely from the
agent's ledger + alert history (no external state):
  * denial ratio       — probing / misconfigured behavior
  * DLP incident rate   — how often its payloads carry secrets/PII
  * exfiltration / prompt-injection alerts — active abuse signals
  * mean risk score     — the adaptive risk signal, averaged

It is descriptive, not itself an enforcement gate; pair it with a policy or the
kill switch if you want it to block.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .models import Alert, Agent, AuditRecord, Decision


@dataclass
class Reputation:
    agent_id: int
    score: int
    band: str  # "trusted" | "watch" | "risky" | "untrusted"
    factors: list[str] = field(default_factory=list)
    sample_size: int = 0

    def as_dict(self) -> dict:
        return {"agent_id": self.agent_id, "score": self.score, "band": self.band,
                "factors": self.factors, "sample_size": self.sample_size}


def _band(score: int) -> str:
    if score >= 85:
        return "trusted"
    if score >= 60:
        return "watch"
    if score >= 35:
        return "risky"
    return "untrusted"


def compute(db: Session, agent: Agent) -> Reputation:
    total = db.scalar(
        select(func.count(AuditRecord.id)).where(
            AuditRecord.agent_id == agent.id, AuditRecord.billable.is_(True))
    ) or 0

    if total == 0:
        # No history yet — neutral-high trust, clearly marked as unproven.
        return Reputation(agent_id=agent.id, score=100, band="trusted",
                          factors=["no_history"], sample_size=0)

    denied = db.scalar(
        select(func.count(AuditRecord.id)).where(
            AuditRecord.agent_id == agent.id, AuditRecord.billable.is_(True),
            AuditRecord.decision == Decision.DENY)
    ) or 0
    # billable-only, so upstream-*response* DLP hits (recorded on non-billable
    # `.result` rows) aren't misattributed to the agent's own payloads — which
    # would let dlp_ratio exceed 1.0 vs. the billable-only denominator.
    dlp_incidents = db.scalar(
        select(func.count(AuditRecord.id)).where(
            AuditRecord.agent_id == agent.id, AuditRecord.billable.is_(True),
            AuditRecord.dlp_count > 0)
    ) or 0
    mean_risk = db.scalar(
        select(func.avg(AuditRecord.risk_score)).where(
            AuditRecord.agent_id == agent.id, AuditRecord.billable.is_(True))
    ) or 0.0
    exfil_alerts = db.scalar(
        select(func.count(Alert.id)).where(
            Alert.agent_id == agent.id,
            Alert.kind.in_(["data_exfiltration", "prompt_injection", "auto_suspend"]))
    ) or 0

    score = 100
    factors: list[str] = []

    denial_ratio = denied / total
    if denial_ratio > 0:
        penalty = min(int(denial_ratio * 50), 50)
        score -= penalty
        factors.append(f"denial_ratio:{denial_ratio:.0%}(-{penalty})")

    dlp_ratio = dlp_incidents / total
    if dlp_ratio > 0:
        penalty = min(int(dlp_ratio * 30), 30)
        score -= penalty
        factors.append(f"dlp_rate:{dlp_ratio:.0%}(-{penalty})")

    if exfil_alerts:
        penalty = min(exfil_alerts * 10, 40)
        score -= penalty
        factors.append(f"abuse_alerts:{exfil_alerts}(-{penalty})")

    if mean_risk >= 20:
        penalty = min(int(mean_risk / 5), 20)
        score -= penalty
        factors.append(f"mean_risk:{mean_risk:.0f}(-{penalty})")

    score = max(0, min(100, score))
    return Reputation(agent_id=agent.id, score=score, band=_band(score),
                      factors=factors or ["clean_history"], sample_size=total)
