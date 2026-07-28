"""Small shared helpers."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

_PREVIEW_LIMIT = 600


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def payload_fingerprint(payload: Any) -> str:
    """SHA-256 over a canonical serialization of the raw payload."""
    return hashlib.sha256(canonical_json(payload).encode()).hexdigest()


def build_preview(redacted: Any) -> str:
    """A short, already-DLP-redacted preview safe to persist in the ledger."""
    if redacted is None:
        return ""
    text = redacted if isinstance(redacted, str) else canonical_json(redacted)
    if len(text) > _PREVIEW_LIMIT:
        return text[:_PREVIEW_LIMIT] + "…"
    return text


# A trailing id-like segment after ':' or '/' (all digits, or a UUID-ish token).
_ID_SEGMENT = re.compile(r"(?<=[:/])(\d+|[0-9a-fA-F]{8,})$")


def resource_family(resource: str) -> str:
    """Collapse a per-instance resource to its *family*.

    ``db:customers:1042`` -> ``db:customers:*``;
    ``http:crm/orders/98`` -> ``http:crm/orders/*``.
    Resources without a trailing id-like segment are returned unchanged.

    One shared definition of "the same kind of resource" is used by both policy
    recommendations (so many per-id denials collapse into one suggested rule) and
    behavioral novelty (so walking ``customers:1..N`` isn't N novel events).
    """
    return _ID_SEGMENT.sub("*", resource)
