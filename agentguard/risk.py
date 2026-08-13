"""Adaptive risk scoring — a 0–100 score for every governed decision.

Static RBAC answers allow/deny; a *risk score* adds a continuous dimension that
drives **adaptive** governance: the same action can sail through when it looks
routine and be escalated to a human when it looks dangerous, without writing a
policy for every combination. The score is a transparent, explainable sum of
weighted factors (never a black box), each recorded so an operator can see
*why* something scored high.

Factors:
  * DLP severity of the payload (critical/high/medium/low)
  * LLM-native attack signatures (prompt injection / jailbreak)
  * whether the action leaves the trust boundary (egress)
  * monetary magnitude (from ``metadata.amount``)
  * resource / action novelty for this agent (behavioral baseline)
  * off-hours activity and recent denial ratio (probing behavior)
  * volume surge vs. the agent's own baseline (z-score)

Two thresholds turn the score into action (both default 0 = off, so scoring is
purely informational until an operator opts in):
  * ``risk_step_up_threshold`` — at/above this, an ALLOW is escalated to
    REQUIRE_APPROVAL (adaptive dual control).
  * ``risk_alert_threshold`` — at/above this, a ``high_risk`` alert is raised.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from . import anomaly
from .config import get_settings
from .models import Agent
from .policy.engine import ActionRequest, PolicyDecision

_LLM_ATTACK_DETECTORS = {
    "prompt_injection", "system_prompt_exfiltration", "jailbreak_persona",
    "jailbreak_dan", "tool_abuse_instruction", "instruction_override_markup",
    "data_exfil_directive", "llm_moderation",
}

_DLP_SEVERITY_WEIGHT = {"critical": 40, "high": 30, "medium": 12, "low": 4}


@dataclass
class RiskAssessment:
    score: int
    factors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"score": self.score, "factors": self.factors}


def _coerce_amount(value) -> float | None:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.replace(",", "").strip())
        except ValueError:
            return None
    return None


def assess(db: Session, agent: Agent, req: ActionRequest, decision: PolicyDecision,
           *, now: datetime | None = None) -> RiskAssessment:
    """Compute the risk score + explanatory factors for a decision."""
    now = now or datetime.now(timezone.utc)
    score = 0
    factors: list[str] = []

    dlp = decision.dlp
    if dlp is not None and dlp.findings:
        detectors = {f.detector for f in dlp.findings}
        if detectors & _LLM_ATTACK_DETECTORS:
            score += 30
            factors.append("llm_attack_signature")
        sev = dlp.max_severity
        if sev in _DLP_SEVERITY_WEIGHT:
            score += _DLP_SEVERITY_WEIGHT[sev]
            factors.append(f"dlp_{sev}")

    if req.is_egress():
        score += 15
        factors.append("egress")

    amount = _coerce_amount((req.metadata or {}).get("amount"))
    if amount is not None and amount > 0:
        bump = min(int(amount / 1000 * 5), 20)
        if bump:
            score += bump
            factors.append(f"amount:{amount:g}")

    # Behavioral baseline signals. All of these come from ONE bounded window
    # fetch (see anomaly.profile) rather than five separate round-trips — the
    # hot path pays a single query for the whole behavioral picture.
    if agent.id is not None:
        prof = anomaly.profile(db, agent.id, req.resource, req.action_type)
        # Novelty is scored per resource *family*, not per literal string: an
        # agent already reading `db:customers:*` isn't doing something new when
        # it reads the next customer id. A genuinely new family still scores.
        if not prof.family_seen:
            score += 15
            factors.append("novel_resource")
        if not prof.action_seen:
            score += 8
            factors.append("novel_action")
        if prof.denial_ratio >= 0.5:
            score += 12
            factors.append(f"denial_ratio:{prof.denial_ratio:.0%}")
        if prof.volume_z >= 3.0:
            score += 12
            factors.append(f"volume_surge:z={prof.volume_z:.1f}")
        # A long run of the identical (action, resource) is the classic
        # stuck-in-a-tool-call-loop failure mode — distinct from a volume spike.
        loop_threshold = get_settings().risk_loop_repeat_threshold
        if loop_threshold and prof.loop_repeats >= loop_threshold:
            score += 12
            factors.append(f"repeat_loop:{prof.loop_repeats}x")

    if anomaly.is_off_hours(now):
        score += 8
        factors.append("off_hours")

    return RiskAssessment(score=min(score, 100), factors=factors)


def step_up_threshold() -> int:
    return get_settings().risk_step_up_threshold


def alert_threshold() -> int:
    return get_settings().risk_alert_threshold


def scoring_enabled() -> bool:
    return get_settings().risk_scoring_enabled
