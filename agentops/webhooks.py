"""Signed outbound webhooks.

Alerts and the SIEM decision stream are POSTed to operator-configured endpoints.
When ``webhook_signing_secret`` is set, each request body is signed with
HMAC-SHA256 and the signature is sent in an ``X-AgentOps-Signature: sha256=<hex>``
header (the same scheme GitHub/Stripe use), so a receiver can verify the payload
really came from this AgentOps instance and was not tampered with in transit.

The body is serialized once here and posted verbatim so the bytes the receiver
verifies are exactly the bytes that were signed.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from typing import Any

from .config import get_settings

_log = logging.getLogger("agentops.webhooks")

_SIGNATURE_HEADER = "X-AgentOps-Signature"


def sign_body(body: bytes, secret: str) -> str:
    """Return the ``sha256=<hex>`` HMAC signature for ``body``."""
    mac = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return f"sha256={mac}"


def verify_signature(body: bytes, header_value: str, secret: str) -> bool:
    """Constant-time verification helper (for receivers / tests)."""
    expected = sign_body(body, secret)
    return hmac.compare_digest(expected, header_value or "")


def post_json(url: str, payload: dict[str, Any], *, timeout: float = 3.0) -> None:
    """POST ``payload`` as JSON, HMAC-signed when a signing secret is configured.

    Best-effort: any transport error is logged and swallowed so a webhook outage
    never affects governance.
    """
    if not url:
        return
    body = json.dumps(payload, default=str, separators=(",", ":")).encode()
    headers = {"Content-Type": "application/json"}
    secret = get_settings().webhook_signing_secret
    if secret:
        headers[_SIGNATURE_HEADER] = sign_body(body, secret)
    try:
        import httpx

        httpx.post(url, content=body, headers=headers, timeout=timeout)
    except Exception as exc:  # noqa: BLE001 — a notification outage must not block governance
        _log.warning("webhook POST to %s failed: %s", url, exc)
