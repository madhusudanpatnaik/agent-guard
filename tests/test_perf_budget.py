"""Hot-path performance budget — guards against latency/query regressions.

The authorization path runs on every agent action, so its cost is a product
constraint, not an implementation detail. These tests assert a *query budget*
rather than wall-clock time: query count is deterministic and portable, while
timing is noisy on shared CI runners.

History: the path once issued 10 queries per authorization (5 of them from risk
scoring alone, each helper doing its own round-trip over the same table). It now
derives every behavioral signal from one bounded window fetch.
"""

from sqlalchemy import event, select

from agentops.config import get_settings
from agentops.database import engine
from agentops.gateway_service import authorize_action, invalidate_detector_cache
from agentops.models import Agent, Effect, Organization, Policy, Role
from agentops.policy.engine import ActionRequest

# Ceilings, not targets — a small margin above measured cost so unrelated
# refactors don't fail the build, but a re-introduced N+1 does.
MAX_QUERIES_STEADY = 8      # measured: 6 (with exact-novelty fallback)
MAX_QUERIES_NO_EXACT = 6    # measured: 5 (bounded-query mode)


class _QueryCounter:
    def __init__(self):
        self.n = 0

    def __enter__(self):
        self.n = 0
        event.listen(engine, "before_cursor_execute", self._on)
        return self

    def __exit__(self, *exc):
        event.remove(engine, "before_cursor_execute", self._on)

    def _on(self, conn, cursor, statement, params, context, executemany):
        self.n += 1


def _perf_agent(db):
    org = db.scalar(select(Organization))
    role = Role(name="perf", org_id=org.id if org else None)
    db.add(role)
    db.flush()
    db.add(Policy(role_id=role.id, effect=Effect.ALLOW, resource="db:**", actions=["read"]))
    agent = Agent(name="PerfBot", role_id=role.id, org_id=org.id if org else None,
                  api_key_hash="perf-h", api_key_prefix="perf", quota=10**9)
    db.add(agent)
    db.commit()
    db.refresh(agent)
    return agent


def test_authorize_query_budget(db):
    """A steady-state authorization must stay within the query budget."""
    agent = _perf_agent(db)
    invalidate_detector_cache()
    authorize_action(db, agent, ActionRequest("read", "db:warm"))  # warm caches

    with _QueryCounter() as qc:
        authorize_action(db, agent, ActionRequest("read", "db:warm"))
    assert qc.n <= MAX_QUERIES_STEADY, (
        f"authorize_action issued {qc.n} queries (budget {MAX_QUERIES_STEADY}) — "
        "a per-request round-trip was likely re-introduced")


def test_authorize_query_budget_bounded_mode(db, monkeypatch):
    """With exact-novelty off, the path must be strictly bounded (no fallbacks)."""
    monkeypatch.setattr(get_settings(), "risk_exact_novelty", False)
    agent = _perf_agent(db)
    invalidate_detector_cache()
    authorize_action(db, agent, ActionRequest("read", "db:warm"))

    with _QueryCounter() as qc:
        authorize_action(db, agent, ActionRequest("read", "db:brand-new-resource"))
    assert qc.n <= MAX_QUERIES_NO_EXACT, (
        f"bounded-mode authorize issued {qc.n} queries (budget {MAX_QUERIES_NO_EXACT})")


def test_query_count_does_not_grow_with_history(db):
    """Cost per authorization must be O(1) in ledger size, not O(history)."""
    agent = _perf_agent(db)
    invalidate_detector_cache()
    for i in range(30):
        authorize_action(db, agent, ActionRequest("read", f"db:seed:{i}"))

    with _QueryCounter() as early:
        authorize_action(db, agent, ActionRequest("read", "db:seed:1"))
    for i in range(60):
        authorize_action(db, agent, ActionRequest("read", f"db:more:{i}"))
    with _QueryCounter() as late:
        authorize_action(db, agent, ActionRequest("read", "db:seed:1"))

    assert late.n <= early.n, (
        f"query count grew with history ({early.n} -> {late.n}) — the hot path "
        "is scaling with ledger size")


def test_detector_cache_avoids_per_request_lookup(db):
    """The custom-detector read must be cached, not paid on every request."""
    from agentops.models import Detector
    org = db.scalar(select(Organization))
    db.add(Detector(org_id=org.id if org else None, name="perf_det",
                    pattern=r"ACME-\d+", severity="high", enabled=True))
    db.commit()
    agent = _perf_agent(db)
    invalidate_detector_cache()

    authorize_action(db, agent, ActionRequest("read", "db:warm"))  # populates cache
    with _QueryCounter() as qc:
        authorize_action(db, agent, ActionRequest("read", "db:warm"))
    cached = qc.n

    invalidate_detector_cache()  # force a reload
    with _QueryCounter() as qc2:
        authorize_action(db, agent, ActionRequest("read", "db:warm"))
    assert qc2.n > cached, "detector lookup does not appear to be cached"
