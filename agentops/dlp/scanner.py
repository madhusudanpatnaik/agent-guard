"""Data-exfiltration / sensitive-data scanner.

Given an arbitrary action payload (dict, list, or scalar) this module walks the
whole structure, string-matches a library of high-signal detectors, validates
candidates where possible (e.g. the Luhn checksum for card numbers, Shannon
entropy for opaque tokens), and returns structured findings together with a
redacted copy of the payload suitable for storage in the audit log.

The design goal is *defense-grade signal*: low false positives, every finding
carries a severity so the policy engine can decide whether to block, redact, or
merely record.
"""

from __future__ import annotations

import math
import re
from dataclasses import asdict, dataclass
from typing import Any

from .deobfuscate import normalized_variants

# --------------------------------------------------------------------------- #
# Severities
# --------------------------------------------------------------------------- #

CRITICAL = "critical"
HIGH = "high"
MEDIUM = "medium"
LOW = "low"

_SEVERITY_RANK = {LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3}


@dataclass
class DLPFinding:
    detector: str
    severity: str
    count: int
    sample: str  # a redacted sample so operators can see *what kind* leaked
    path: str = ""  # JSON-ish path to where it was found

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _luhn_ok(number: str) -> bool:
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def _redact(value: str, keep: int = 4) -> str:
    value = value.strip()
    if len(value) <= keep:
        return "*" * len(value)
    return value[:keep] + "*" * min(len(value) - keep, 12)


# --------------------------------------------------------------------------- #
# Detectors
# --------------------------------------------------------------------------- #

@dataclass
class _Detector:
    name: str
    pattern: re.Pattern
    severity: str
    validator: Any = None  # optional callable(match_str) -> bool


_DETECTORS: list[_Detector] = [
    _Detector(
        "aws_access_key_id",
        re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
        CRITICAL,
    ),
    _Detector(
        "aws_secret_access_key",
        re.compile(r"\baws_secret_access_key\b\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})"),
        CRITICAL,
    ),
    _Detector(
        "private_key_block",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"),
        CRITICAL,
    ),
    _Detector(
        "google_api_key",
        re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
        CRITICAL,
    ),
    _Detector(
        "slack_token",
        re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,48}\b"),
        CRITICAL,
    ),
    _Detector(
        "github_token",
        re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b"),
        CRITICAL,
    ),
    _Detector(
        "stripe_secret_key",
        re.compile(r"\b(sk|rk)_(live|test)_[0-9A-Za-z]{16,}\b"),
        CRITICAL,
    ),
    _Detector(
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b"),
        HIGH,
    ),
    _Detector(
        "credit_card",
        re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
        HIGH,
        validator=_luhn_ok,
    ),
    _Detector(
        "us_ssn",
        re.compile(r"\b(?!000|666|9\d\d)\d{3}[- ]?(?!00)\d{2}[- ]?(?!0000)\d{4}\b"),
        HIGH,
    ),
    _Detector(
        "email_address",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        MEDIUM,
    ),
    _Detector(
        "us_phone",
        re.compile(r"\b(?:\+1[-. ]?)?\(?\d{3}\)?[-. ]?\d{3}[-. ]?\d{4}\b"),
        LOW,
    ),
    _Detector(
        "ip_address",
        re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        LOW,
    ),
    _Detector(
        "generic_secret_assignment",
        re.compile(
            r"(?i)\b(?:password|passwd|secret|api[_-]?key|token|authorization|bearer)\b"
            r"\s*[=:]\s*['\"]?([^\s'\"]{6,})"
        ),
        HIGH,
    ),
]

# Keys whose *value* is treated as an opaque secret if it looks high-entropy.
_HIGH_ENTROPY_MIN_LEN = 20
_HIGH_ENTROPY_THRESHOLD = 4.0


class DLPScanner:
    """Stateless scanner. Instantiate once and reuse; it holds no mutable state."""

    def __init__(self, detectors: list[_Detector] | None = None, *,
                 deobfuscate: bool = True):
        self.detectors = detectors if detectors is not None else _DETECTORS
        # Also scan base64/hex/spaced/zero-width readings of each string.
        self.deobfuscate = deobfuscate

    # -- public API -------------------------------------------------------
    def scan(self, payload: Any) -> "DLPResult":
        findings: dict[tuple[str, str], DLPFinding] = {}
        redacted = self._walk(payload, path="$", findings=findings)
        ordered = sorted(
            findings.values(),
            key=lambda f: (-_SEVERITY_RANK[f.severity], f.detector),
        )
        return DLPResult(findings=ordered, redacted=redacted)

    # -- internals --------------------------------------------------------
    def _walk(
        self,
        node: Any,
        path: str,
        findings: dict[tuple[str, str], DLPFinding],
    ) -> Any:
        if isinstance(node, dict):
            return {
                k: self._walk(v, f"{path}.{k}", findings) for k, v in node.items()
            }
        if isinstance(node, (list, tuple)):
            return [self._walk(v, f"{path}[{i}]", findings) for i, v in enumerate(node)]
        if isinstance(node, str):
            return self._scan_string(node, path, findings)
        return node

    def _scan_string(
        self,
        text: str,
        path: str,
        findings: dict[tuple[str, str], DLPFinding],
    ) -> str:
        redacted = text
        for det in self.detectors:
            # Redact all matches for this detector in a SINGLE linear pass. Doing
            # a str.replace per match is O(matches x length) and lets an attacker
            # DoS the scanner with a payload full of tiny matches.
            state: dict[str, Any] = {"count": 0, "sample": ""}

            def _sub(match: "re.Match", _det=det, _state=state) -> str:
                raw = match.group(0)
                if _det.validator and not _det.validator(raw):
                    return raw  # not a real match; leave as-is
                _state["count"] += 1
                if not _state["sample"]:
                    _state["sample"] = _redact(raw)
                return f"[REDACTED:{_det.name}]"

            redacted = det.pattern.sub(_sub, redacted)
            if state["count"]:
                key = (det.name, path)
                existing = findings.get(key)
                if existing:
                    existing.count += state["count"]
                else:
                    findings[key] = DLPFinding(
                        detector=det.name,
                        severity=det.severity,
                        count=state["count"],
                        sample=state["sample"],
                        path=path,
                    )

        # High-entropy opaque token heuristic (catches unknown secret formats).
        stripped = text.strip()
        if (
            "[REDACTED" not in redacted
            and len(stripped) >= _HIGH_ENTROPY_MIN_LEN
            and " " not in stripped
            and _shannon_entropy(stripped) >= _HIGH_ENTROPY_THRESHOLD
        ):
            key = ("high_entropy_token", path)
            if key not in findings:
                findings[key] = DLPFinding(
                    detector="high_entropy_token",
                    severity=MEDIUM,
                    count=1,
                    sample=_redact(stripped),
                    path=path,
                )
            redacted = "[REDACTED:high_entropy_token]"

        # Obfuscation pass: a secret that is base64/hex-encoded, spaced out, or
        # zero-width-split reads as innocuous text to the literal patterns above.
        # Re-run the detectors over bounded normalized readings of the string and
        # record any hit. The *findings* come from the variants; the returned
        # `redacted` text is never replaced by a decoded form, so normalization
        # can only ever add detection — it cannot corrupt the payload.
        if self.deobfuscate:
            for variant in normalized_variants(text):
                for det in self.detectors:
                    for match in det.pattern.finditer(variant):
                        raw = match.group(0)
                        if det.validator and not det.validator(raw):
                            continue
                        key = (det.name, path)
                        if key not in findings:
                            findings[key] = DLPFinding(
                                detector=det.name, severity=det.severity, count=1,
                                sample=_redact(raw), path=path,
                            )
                        # The literal text hid a real secret — don't emit it.
                        if "[REDACTED" not in redacted:
                            redacted = f"[REDACTED:obfuscated_{det.name}]"
                        break
        return redacted


@dataclass
class DLPResult:
    findings: list[DLPFinding]
    redacted: Any = None

    @property
    def has_findings(self) -> bool:
        return bool(self.findings)

    @property
    def max_severity(self) -> str | None:
        if not self.findings:
            return None
        return max(self.findings, key=lambda f: _SEVERITY_RANK[f.severity]).severity

    @property
    def blocking(self) -> bool:
        """True if any finding is HIGH or CRITICAL (exfiltration-grade)."""
        return any(_SEVERITY_RANK[f.severity] >= _SEVERITY_RANK[HIGH] for f in self.findings)

    def findings_as_dicts(self) -> list[dict[str, Any]]:
        return [f.as_dict() for f in self.findings]


# Shared default instance + convenience function.
default_scanner = DLPScanner()


def scan_payload(payload: Any) -> DLPResult:
    return default_scanner.scan(payload)


# --------------------------------------------------------------------------- #
# Operator-defined custom detectors (org-scoped, merged with built-ins)
# --------------------------------------------------------------------------- #

_MAX_PATTERN_LEN = 512
_custom_cache: dict[tuple[str, str, str], _Detector] = {}


def compile_custom_detector(name: str, pattern: str, severity: str) -> _Detector | None:
    """Compile an operator detector spec into a ``_Detector`` (cached).

    Returns None if the pattern is too long, fails to compile, or the severity
    is not a recognized level — so one bad custom rule can never break scanning.
    """
    if not name or not pattern or len(pattern) > _MAX_PATTERN_LEN:
        return None
    if severity not in _SEVERITY_RANK:
        return None
    key = (name, pattern, severity)
    cached = _custom_cache.get(key)
    if cached is not None:
        return cached
    try:
        compiled = re.compile(pattern)
    except re.error:
        return None
    det = _Detector(name=name, pattern=compiled, severity=severity)
    _custom_cache[key] = det
    return det


def scanner_with_custom(specs: list[dict] | None) -> DLPScanner:
    """Build a scanner running the built-ins plus valid custom detectors."""
    if not specs:
        return default_scanner
    extra = [
        det for s in specs
        if (det := compile_custom_detector(
            s.get("name", ""), s.get("pattern", ""), s.get("severity", "high"))) is not None
    ]
    if not extra:
        return default_scanner
    return DLPScanner(_DETECTORS + extra)


def scan_payload_custom(payload: Any, specs: list[dict] | None) -> DLPResult:
    """Scan with built-ins + the given custom detector specs."""
    return scanner_with_custom(specs).scan(payload)
