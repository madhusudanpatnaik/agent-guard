"""Signed outbound webhooks.

Alerts and the SIEM decision stream are POSTed to operator-configured endpoints.
When ``webhook_signing_secret`` is set, each request body is signed with
HMAC-SHA256 and the signature is sent in an ``X-AgentGuard-Signature: sha256=<hex>``
header (the same scheme GitHub/Stripe use), so a receiver can verify the payload
really came from this AgentGuard instance and was not tampered with in transit.

The body is serialized once here and posted verbatim so the bytes the receiver
verifies are exactly the bytes that were signed.

Delivery is off the caller's thread entirely (see the dispatcher below) — every
caller here is ``ledger.append()``, an alert, or an approval notification, i.e.
the governance hot path, and "best-effort, must never affect governance" has to
be true for a *slow* endpoint too, not just one that fails outright.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import queue
import threading
from typing import Any

from .config import get_settings

_log = logging.getLogger("agentguard.webhooks")

_SIGNATURE_HEADER = "X-AgentGuard-Signature"


def sign_body(body: bytes, secret: str) -> str:
    """Return the ``sha256=<hex>`` HMAC signature for ``body``."""
    mac = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return f"sha256={mac}"


def verify_signature(body: bytes, header_value: str, secret: str) -> bool:
    """Constant-time verification helper (for receivers / tests)."""
    expected = sign_body(body, secret)
    return hmac.compare_digest(expected, header_value or "")


# --------------------------------------------------------------------------- #
# Background dispatch
#
# Measured: a webhook endpoint that merely responds slowly (2s), rather than
# failing outright, blocked ledger.append() for the full 2s — and every
# authorize_action() in the product calls append() inline. The docstring's
# "a webhook outage never affects governance" was true for a hard failure
# (connection refused fails fast) but false for a slow one, which is the more
# realistic degradation mode for a real SIEM/Slack/PagerDuty endpoint under load.
#
# One background thread drains a bounded queue; a caller-observed delay would
# now come from the queue filling, not from HTTP I/O, so a `put_nowait` in the
# request path stays microseconds regardless of how slow the receiver is. A
# full queue means the receiver has been unhealthy for a while — dropping the
# newest notification with a log warning is the correct trade-off; blocking the
# request path to avoid the drop would reintroduce the exact bug this fixes.
# --------------------------------------------------------------------------- #

_QUEUE_MAXSIZE = 1000
_queue: queue.Queue = queue.Queue(maxsize=_QUEUE_MAXSIZE)
_dispatcher_lock = threading.Lock()
_dispatcher_started = False


def _deliver(url: str, body: bytes, headers: dict[str, str], timeout: float) -> None:
    try:
        import httpx

        httpx.post(url, content=body, headers=headers, timeout=timeout)
    except Exception as exc:  # noqa: BLE001 — a notification outage must not block governance
        _log.warning("webhook POST to %s failed: %s", url, exc)
    finally:
        _queue.task_done()


def _dispatcher_loop() -> None:
    while True:
        _deliver(*_queue.get())


def _ensure_dispatcher() -> None:
    global _dispatcher_started
    if _dispatcher_started:
        return
    with _dispatcher_lock:
        if _dispatcher_started:
            return
        threading.Thread(
            target=_dispatcher_loop, name="agentguard-webhook-dispatch", daemon=True
        ).start()
        _dispatcher_started = True


def flush_pending_webhooks(timeout: float = 5.0) -> bool:
    """Block until every currently-queued webhook has been delivered (or dropped).

    Not used by production code — request-path callers must never wait on
    delivery, which is the entire point of the dispatcher. For tests that need
    deterministic ordering instead of a delivery race against an assertion.
    Returns False (rather than hanging) if delivery does not finish in time.
    """
    done = threading.Event()

    def _wait() -> None:
        _queue.join()
        done.set()

    threading.Thread(target=_wait, daemon=True).start()
    return done.wait(timeout)


def post_json(url: str, payload: dict[str, Any], *, timeout: float = 3.0) -> None:
    """Enqueue ``payload`` as JSON for background delivery, HMAC-signed when a
    signing secret is configured. Returns immediately — this function does no
    network I/O itself; see the dispatcher above for why that matters.
    """
    if not url:
        return
    body = json.dumps(payload, default=str, separators=(",", ":")).encode()
    headers = {"Content-Type": "application/json"}
    secret = get_settings().webhook_signing_secret
    if secret:
        headers[_SIGNATURE_HEADER] = sign_body(body, secret)
    _ensure_dispatcher()
    try:
        _queue.put_nowait((url, body, headers, timeout))
    except queue.Full:
        _log.warning(
            "webhook queue full (%d pending); dropping notification to %s — "
            "the receiver has likely been unhealthy for a while", _QUEUE_MAXSIZE, url,
        )
