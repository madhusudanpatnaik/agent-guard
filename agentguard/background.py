"""Background tasks for the AgentGuard control plane.

Registers lightweight asyncio tasks that run alongside the FastAPI event loop:

* **Approval + containment sweeper** — every 60 seconds, transitions stale
  pending approvals to ``expired`` and auto-lifts any time-bound org containment
  whose window has elapsed, so both happen proactively rather than only lazily.

* **Ledger re-verifier** — every 10 minutes, runs the full O(n) chain walk and
  refreshes the verified-prefix cache. The dashboard's cached integrity check
  cannot see an edit of a *historic* row that leaves the head untouched; this
  bounds that blind spot to one interval (and logs loudly if the chain breaks).
"""

from __future__ import annotations

import asyncio
import logging

from .approvals_service import sweep_expired
from .audit.ledger import verify_chain
from .containment import sweep_expired as sweep_containment
from .database import SessionLocal

_log = logging.getLogger("agentguard.background")

_SWEEP_INTERVAL_SECONDS = 60
_VERIFY_INTERVAL_SECONDS = 600


async def _approval_sweeper() -> None:
    """Periodic sweeper: expire stale pending approvals."""
    while True:
        try:
            await asyncio.sleep(_SWEEP_INTERVAL_SECONDS)
            with SessionLocal() as db:
                count = sweep_expired(db)
                if count:
                    _log.info("Approval sweeper: expired %d stale approval(s)", count)
                lifted = sweep_containment(db)
                if lifted:
                    _log.info("Containment sweeper: auto-lifted %d expired freeze(s)", lifted)
        except asyncio.CancelledError:
            break
        except Exception:
            _log.exception("Approval sweeper iteration failed (will retry)")


async def _ledger_reverifier() -> None:
    """Periodic full chain verification; refreshes the verified-prefix cache."""
    while True:
        try:
            await asyncio.sleep(_VERIFY_INTERVAL_SECONDS)
            status = await asyncio.to_thread(_verify_once)
            if not status.valid:
                _log.error(
                    "AUDIT LEDGER INTEGRITY FAILURE: %s (broken at seq %s)",
                    status.detail, status.broken_at_seq,
                )
        except asyncio.CancelledError:
            break
        except Exception:
            _log.exception("Ledger re-verify iteration failed (will retry)")


def _verify_once():
    with SessionLocal() as db:
        return verify_chain(db)


_tasks: list[asyncio.Task] = []


def start_background_tasks() -> None:
    """Start all background tasks. Call once during app lifespan startup."""
    _tasks.append(asyncio.create_task(_approval_sweeper()))
    _tasks.append(asyncio.create_task(_ledger_reverifier()))
    _log.info(
        "Background tasks started (approval sweep=%ds, ledger re-verify=%ds)",
        _SWEEP_INTERVAL_SECONDS, _VERIFY_INTERVAL_SECONDS,
    )


def stop_background_tasks() -> None:
    """Cancel all background tasks. Call during app lifespan shutdown."""
    for task in _tasks:
        if not task.done():
            task.cancel()
    if _tasks:
        _log.info("Background tasks stopped")
    _tasks.clear()
