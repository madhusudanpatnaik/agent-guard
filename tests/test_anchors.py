"""Tests for the distributed audit-anchoring backends."""

import hashlib

import httpx

from agentguard.audit import anchors
from agentguard.audit.anchors import (
    FileAnchor,
    RFC3161Anchor,
    TransparencyLogAnchor,
    build_timestamp_request,
)
from agentguard.config import get_settings


# --- file backend -----------------------------------------------------------

def test_file_anchor_appends(tmp_path):
    path = tmp_path / "anchor.log"
    fa = FileAnchor(str(path))
    fa.anchor(0, "hash0")
    fa.anchor(1, "hash1")
    lines = path.read_text().strip().splitlines()
    assert lines == ["0\thash0", "1\thash1"]


# --- RFC-3161 request encoding ---------------------------------------------

def _der_read_len(data, i):
    n = data[i]
    i += 1
    if n < 0x80:
        return n, i
    count = n & 0x7F
    val = int.from_bytes(data[i:i + count], "big")
    return val, i + count


def test_timestamp_request_is_valid_der_over_the_digest():
    digest = hashlib.sha256(b"deadbeef").digest()
    req = build_timestamp_request(digest, nonce=12345)
    # Top-level SEQUENCE.
    assert req[0] == 0x30
    total, i = _der_read_len(req, 1)
    assert total == len(req) - i
    # version INTEGER 1 comes first.
    assert req[i] == 0x02
    vlen, j = _der_read_len(req, i + 1)
    assert req[j:j + vlen] == b"\x01"
    # The SHA-256 digest must appear verbatim (inside the messageImprint).
    assert digest in req
    # The SHA-256 OID must be present.
    assert bytes([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]) in req


def test_rfc3161_anchor_posts_and_stores_token(tmp_path, monkeypatch):
    captured = {}

    def fake_post(url, **kw):
        captured["url"] = url
        captured["content"] = kw.get("content")
        captured["ct"] = kw.get("headers", {}).get("Content-Type")
        return httpx.Response(200, content=b"\x30\x03fake-token-bytes",
                              request=httpx.Request("POST", url))

    monkeypatch.setattr(httpx, "post", fake_post)
    anchor = RFC3161Anchor("http://tsa.local/tsr", str(tmp_path / "tsr"))
    anchor.anchor(7, "abc123")

    assert captured["url"] == "http://tsa.local/tsr"
    assert captured["ct"] == "application/timestamp-query"
    # The request body is a TimeStampReq over sha256(head_hash).
    assert hashlib.sha256(b"abc123").digest() in captured["content"]
    token = (tmp_path / "tsr" / "000000000007.tsr").read_bytes()
    assert token.endswith(b"fake-token-bytes")


def test_rfc3161_anchor_failure_is_swallowed(tmp_path, monkeypatch):
    def boom(url, **kw):
        raise httpx.ConnectError("no tsa")

    monkeypatch.setattr(httpx, "post", boom)
    RFC3161Anchor("http://tsa.local/tsr", str(tmp_path / "tsr")).anchor(1, "h")  # must not raise


# --- transparency log -------------------------------------------------------

def test_transparency_log_anchor_posts_head(monkeypatch):
    captured = {}

    def fake_post(url, **kw):
        captured["url"] = url
        captured["json"] = kw.get("json")
        return httpx.Response(200, json={"logIndex": 42}, request=httpx.Request("POST", url))

    monkeypatch.setattr(httpx, "post", fake_post)
    TransparencyLogAnchor("http://rekor.local/api/v1/log/entries").anchor(3, "headhash")
    assert captured["json"]["seq"] == 3
    assert captured["json"]["hash"] == "headhash"


# --- dispatch ---------------------------------------------------------------

def test_anchor_head_dispatches_to_all_configured_backends(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(get_settings(), "audit_anchor_backends",
                        ["file", "transparency_log"])
    monkeypatch.setattr(get_settings(), "audit_anchor_path", str(tmp_path / "a.log"))
    monkeypatch.setattr(get_settings(), "transparency_log_url", "http://rekor.local/log")
    monkeypatch.setattr(httpx, "post",
                        lambda url, **kw: calls.append(url) or httpx.Response(
                            200, json={"logIndex": 1}, request=httpx.Request("POST", url)))
    anchors.reset_anchor_cache()

    anchors.anchor_head(0, "h0")
    # file written…
    assert (tmp_path / "a.log").read_text().strip() == "0\th0"
    # …and the transparency log POSTed.
    assert calls == ["http://rekor.local/log"]
    anchors.reset_anchor_cache()
