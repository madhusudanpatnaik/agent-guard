"""Small shared helpers."""

from __future__ import annotations

import hashlib
import json
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
