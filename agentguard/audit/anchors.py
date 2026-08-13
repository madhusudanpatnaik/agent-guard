"""Distributed audit anchoring backends.

The in-DB hash chain proves *internal* consistency; anchoring the head to an
independent store proves it to a *third party* and survives loss of the local
node (an ephemeral Kubernetes pod losing its file anchor). Backends are
composable via ``audit_anchor_backends``:

* **file** (default) — append ``seq<TAB>hash`` to ``audit_anchor_path``. This is
  also what :func:`agentguard.audit.ledger.verify_chain` reads to detect head
  truncation, so it stays on by default.
* **transparency_log** — POST each head to a Rekor-style transparency log; the
  returned log index / UUID is externally auditable and append-only.
* **rfc3161** — obtain an RFC-3161 signed timestamp token from a Time-Stamp
  Authority over the head hash, proving the head existed at a point in time
  without trusting AgentGuard. Tokens are written under ``<anchor>.tsr/``.

All backends are best-effort: an anchoring outage logs a warning but never
blocks a ledger append (the write path must stay available).
"""

from __future__ import annotations

import hashlib
import logging
from functools import lru_cache
from pathlib import Path

from ..config import get_settings

_log = logging.getLogger("agentguard.audit.anchors")


class AnchorBackend:
    def anchor(self, seq: int, head_hash: str) -> None:
        raise NotImplementedError

    def name(self) -> str:
        return type(self).__name__


class FileAnchor(AnchorBackend):
    """Append the head to the local out-of-band anchor file."""

    def __init__(self, path: str):
        self.path = path

    def anchor(self, seq: int, head_hash: str) -> None:
        if not self.path:
            return
        try:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(f"{seq}\t{head_hash}\n")
        except OSError as exc:
            _log.warning("file anchor write failed: %s", exc)


class TransparencyLogAnchor(AnchorBackend):
    """POST the head to a Rekor-style transparency log (append-only, public)."""

    def __init__(self, url: str):
        self.url = url

    def anchor(self, seq: int, head_hash: str) -> None:
        if not self.url:
            return
        try:
            import httpx

            resp = httpx.post(self.url, json={"seq": seq, "hash": head_hash,
                                              "kind": "agentguard.ledger.head"}, timeout=3.0)
            resp.raise_for_status()
            body = resp.json() if resp.content else {}
            ref = body.get("uuid") or body.get("logIndex") or body.get("id")
            _log.info("ledger head seq=%d anchored to transparency log (ref=%s)", seq, ref)
        except Exception as exc:  # noqa: BLE001
            _log.warning("transparency-log anchor failed: %s", exc)


# --- Minimal DER encoding for an RFC-3161 TimeStampReq ---------------------- #

def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    out = b""
    while n:
        out = bytes([n & 0xFF]) + out
        n >>= 8
    return bytes([0x80 | len(out)]) + out


def _der(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(body)) + body


def _der_int(value: int) -> bytes:
    if value == 0:
        return _der(0x02, b"\x00")
    body = b""
    v = value
    while v:
        body = bytes([v & 0xFF]) + body
        v >>= 8
    if body[0] & 0x80:  # keep it positive
        body = b"\x00" + body
    return _der(0x02, body)


# OID 2.16.840.1.101.3.4.2.1 (sha256), pre-encoded.
_SHA256_OID = bytes([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01])


def build_timestamp_request(digest: bytes, *, nonce: int, cert_req: bool = True) -> bytes:
    """DER-encode an RFC-3161 TimeStampReq over a SHA-256 ``digest``."""
    algorithm = _der(0x30, _SHA256_OID + _der(0x05, b""))          # AlgorithmIdentifier + NULL
    message_imprint = _der(0x30, algorithm + _der(0x04, digest))    # MessageImprint
    body = _der_int(1) + message_imprint + _der_int(nonce)          # version, imprint, nonce
    if cert_req:
        body += _der(0x01, b"\xff")                                 # certReq BOOLEAN TRUE
    return _der(0x30, body)


class RFC3161Anchor(AnchorBackend):
    """Fetch and store an RFC-3161 timestamp token over the ledger head hash."""

    def __init__(self, tsa_url: str, out_dir: str):
        self.tsa_url = tsa_url
        self.out_dir = Path(out_dir)

    def anchor(self, seq: int, head_hash: str) -> None:
        if not self.tsa_url:
            return
        try:
            import httpx

            digest = hashlib.sha256(head_hash.encode()).digest()
            # A deterministic-but-unique nonce keyed on the head (no RNG at import).
            nonce = int.from_bytes(digest[:8], "big")
            req = build_timestamp_request(digest, nonce=nonce)
            resp = httpx.post(self.tsa_url, content=req, timeout=5.0,
                              headers={"Content-Type": "application/timestamp-query"})
            resp.raise_for_status()
            self.out_dir.mkdir(parents=True, exist_ok=True)
            token_path = self.out_dir / f"{seq:012d}.tsr"
            token_path.write_bytes(resp.content)
            _log.info("ledger head seq=%d timestamped by TSA -> %s", seq, token_path)
        except Exception as exc:  # noqa: BLE001
            _log.warning("RFC-3161 anchor failed: %s", exc)


@lru_cache
def _backends() -> tuple[AnchorBackend, ...]:
    settings = get_settings()
    names = settings.audit_anchor_backends or ["file"]
    built: list[AnchorBackend] = []
    for name in names:
        n = name.lower()
        if n == "file":
            built.append(FileAnchor(settings.audit_anchor_path))
        elif n == "transparency_log":
            built.append(TransparencyLogAnchor(settings.transparency_log_url))
        elif n == "rfc3161":
            built.append(RFC3161Anchor(settings.rfc3161_tsa_url,
                                       (settings.audit_anchor_path or "./agentguard-ledger-anchor")
                                       + ".tsr"))
        else:
            _log.warning("unknown audit anchor backend %r; ignoring", name)
    return tuple(built)


def anchor_head(seq: int, head_hash: str) -> None:
    """Dispatch a new head to every configured anchor backend (best-effort)."""
    for backend in _backends():
        backend.anchor(seq, head_hash)


def reset_anchor_cache() -> None:
    """Drop the cached backend set (tests / after a settings change)."""
    _backends.cache_clear()
