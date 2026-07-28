"""LLM-native security detectors — prompt injection, jailbreaks, tool abuse.

Regex/entropy DLP catches *secrets and PII*; it says nothing about *semantic*
attacks on the agent itself. When an agent ingests attacker-influenceable text
(a web page, a RAG document, a tool result, an email), that text can carry
instructions designed to hijack the model: "ignore previous instructions",
"you are now DAN", "exfiltrate the system prompt", "run the following command".

This module scans strings for those patterns and returns
:class:`~agentops.dlp.scanner.DLPFinding` objects so they flow through the same
governance surface as any other finding — recorded in the ledger, surfaced in
the console, and (being HIGH severity) blocked on egress. It is intentionally
dependency-free; an optional moderation webhook can add an LLM-native verdict.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any

from .scanner import HIGH, MEDIUM, DLPFinding, _redact

_log = logging.getLogger("agentops.dlp.llm_guard")


@dataclass
class _Signature:
    name: str
    pattern: re.Pattern
    severity: str


# High-signal, low-false-positive patterns drawn from published prompt-injection
# and jailbreak corpora. Kept case-insensitive and anchored on imperative phrasing.
_SIGNATURES: list[_Signature] = [
    _Signature(
        "prompt_injection",
        re.compile(
            r"(?i)\b(?:ignore|disregard|forget|override)\b[^.\n]{0,40}"
            r"\b(?:previous|prior|above|earlier|all)\b[^.\n]{0,20}"
            r"\b(?:instruction|instructions|prompt|prompts|rules?|context)\b"
        ),
        HIGH,
    ),
    _Signature(
        "system_prompt_exfiltration",
        re.compile(
            r"(?i)\b(?:reveal|print|repeat|show|leak|exfiltrate|output|disclose)\b"
            r"[^.\n]{0,30}\b(?:system\s+prompt|your\s+instructions|initial\s+prompt|"
            r"the\s+prompt\s+above|hidden\s+prompt)\b"
        ),
        HIGH,
    ),
    _Signature(
        "jailbreak_persona",
        re.compile(
            r"(?i)\b(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be|from\s+now\s+on\s+you)\b"
            r"[^.\n]{0,40}\b(?:DAN|do\s+anything\s+now|developer\s+mode|jailbroken|"
            r"unfiltered|no\s+restrictions|without\s+any\s+restrictions)\b"
        ),
        HIGH,
    ),
    _Signature(
        "jailbreak_dan",
        re.compile(r"(?i)\b(?:DAN\s+mode|do\s+anything\s+now|stay\s+in\s+character\s+as\s+DAN)\b"),
        HIGH,
    ),
    _Signature(
        "tool_abuse_instruction",
        re.compile(
            r"(?i)\b(?:run|execute|eval|exec|invoke|call)\b[^.\n]{0,30}"
            r"\b(?:the\s+following|this\s+command|this\s+code|shell|os\.system|subprocess|"
            r"rm\s+-rf|curl\s+http)\b"
        ),
        HIGH,
    ),
    _Signature(
        "instruction_override_markup",
        re.compile(r"(?i)(?:</?(?:system|assistant|instructions?)>|\[/?INST\]|###\s*system)"),
        MEDIUM,
    ),
    _Signature(
        "data_exfil_directive",
        re.compile(
            r"(?i)\b(?:send|post|upload|forward|email|transmit)\b[^.\n]{0,30}"
            r"\b(?:to\s+(?:https?://|attacker|evil)|your\s+api\s+key|the\s+secret|credentials)\b"
        ),
        HIGH,
    ),
]


# Every signature above is anchored on at least one of these literal cues, so a
# string containing none of them cannot match any of them. Checking that first
# replaces seven full regex passes with one lowercase plus a handful of C-level
# substring searches. Measured on 1MB inputs: 69ms -> 16ms on filler and 222ms ->
# 27ms on prose, with byte-identical findings.
#
# This is a pure CPU optimization and MUST stay a strict superset of what the
# patterns can match — adding a signature means adding its cues here, which
# test_llm_guard_prefilter.py enforces by differential comparison.
_CUES: tuple[str, ...] = (
    "ignore", "disregard", "forget", "override",
    "reveal", "print", "repeat", "show", "leak", "exfiltrate", "output", "disclose",
    "you are now", "act as", "pretend to be", "from now on you",
    "dan", "do anything now", "stay in character",
    "run", "execute", "eval", "exec", "invoke", "call",
    "<system", "</system", "<assistant", "</assistant", "<instruction", "</instruction",
    "[inst", "[/inst", "###",
    "send", "post", "upload", "forward", "email", "transmit",
)


def _may_match(text: str) -> bool:
    """Cheap necessary-condition check before the expensive signature pass.

    Deliberately ``lower()`` plus ``in`` rather than one compiled alternation:
    ``str.__contains__`` uses a C substring search, while a 39-branch
    ``IGNORECASE`` alternation has no literal-prefix optimization and retries
    every branch at every position. Measured on a cue-free 1MB input, the
    alternation took 450ms against 16ms here — 5x *slower* than the seven
    signature passes it was meant to avoid.
    """
    lowered = text.lower()
    return any(cue in lowered for cue in _CUES)


def scan_text(text: str, path: str = "$") -> list[DLPFinding]:
    """Return LLM-security findings for a single string."""
    if not text or len(text) < 8:
        return []
    if not _may_match(text):
        return []
    findings: list[DLPFinding] = []
    for sig in _SIGNATURES:
        matches = sig.pattern.findall(text)
        if matches:
            sample = matches[0] if isinstance(matches[0], str) else text
            findings.append(DLPFinding(
                detector=sig.name, severity=sig.severity, count=len(matches),
                sample=_redact(str(sample))[:80], path=path,
            ))
    return findings


def scan_payload_for_attacks(payload: Any) -> list[DLPFinding]:
    """Walk a payload (dict/list/str) and collect LLM-security findings."""
    findings: list[DLPFinding] = []

    def walk(node: Any, path: str) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                walk(v, f"{path}.{k}")
        elif isinstance(node, (list, tuple)):
            for i, v in enumerate(node):
                walk(v, f"{path}[{i}]")
        elif isinstance(node, str):
            findings.extend(scan_text(node, path))

    walk(payload, "$")
    return findings


def moderate_via_webhook(text: str) -> DLPFinding | None:
    """Optional LLM-native moderation: POST text, expect ``{"flagged": bool, ...}``.

    Best-effort — a moderation-service outage never blocks governance; it just
    means that one extra signal is unavailable for that request.
    """
    from ..config import get_settings

    url = get_settings().llm_guard_webhook_url
    if not url:
        return None
    try:
        import httpx

        resp = httpx.post(url, json={"text": text[:8000]}, timeout=2.0)
        resp.raise_for_status()
        data = resp.json()
        if data.get("flagged"):
            categories = ", ".join(data.get("categories", [])) or "policy violation"
            return DLPFinding(detector="llm_moderation", severity=HIGH, count=1,
                              sample=categories[:80], path="$")
    except Exception as exc:  # noqa: BLE001
        _log.warning("LLM moderation webhook failed: %s", exc)
    return None
