"""Obfuscation normalization for DLP scanning.

Regex detectors match *literal* shapes, which an LLM (or an attacker steering
one) defeats with near-zero effort:

    AKIAIOSFODNN7EXAMPLE            -> caught
    QUtJQUlPU0ZPRE5ON0VYQU1QTEU=    -> base64, missed
    A K I A I O S F O D N N 7 ...   -> spaced, missed
    AKIA​IOSFODNN7EXAMPLE      -> zero-width joiner, missed
    AKIA...               -> unicode escapes, missed

This module produces a small set of *normalized variants* of a string so the
existing detector battery can be run against each. It is deliberately:

* **bounded** — a fixed number of variants, each length-capped, with no
  recursive decoding, so a "decode bomb" cannot amplify work;
* **additive** — variants are only ever used to FIND secrets, never to replace
  the redacted output, so normalization can't corrupt a payload;
* **conservative** — a decode is kept only if it yields mostly-printable text,
  which keeps random base64-looking data from becoming noise.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
import unicodedata

# Bounds: keep the work per string strictly finite.
MAX_INPUT = 8192      # only normalize reasonably sized strings
MAX_VARIANTS = 4      # at most this many extra forms per string

# Characters that carry no visual meaning but break a regex: zero-width space,
# ZWNJ/ZWJ, word joiner, BOM, and soft hyphen.
_INVISIBLE = dict.fromkeys(map(ord, "​‌‍⁠﻿­"), None)

_B64_CANDIDATE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_HEX_CANDIDATE = re.compile(r"(?:[0-9a-fA-F]{2}){8,}")
_SEPARATED = re.compile(r"(?:[A-Za-z0-9][\s._\-]){7,}[A-Za-z0-9]")


def _mostly_printable(text: str) -> bool:
    """True if a decode looks like real text rather than binary noise."""
    if not text:
        return False
    printable = sum(1 for ch in text if ch.isprintable())
    return printable / len(text) >= 0.9


def _strip_invisible(text: str) -> str:
    return text.translate(_INVISIBLE)


def _collapse_separators(text: str) -> str:
    """Remove separators inside runs that look like a deliberately split token."""
    out = text
    for match in _SEPARATED.finditer(text):
        out = out.replace(match.group(0), re.sub(r"[\s._\-]", "", match.group(0)))
    return out


def _decode_base64(text: str) -> list[str]:
    found: list[str] = []
    for match in _B64_CANDIDATE.finditer(text):
        blob = match.group(0)
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
            decoded = raw.decode("utf-8", "strict")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if _mostly_printable(decoded):
            found.append(decoded)
    return found


def _decode_hex(text: str) -> list[str]:
    found: list[str] = []
    for match in _HEX_CANDIDATE.finditer(text):
        try:
            decoded = bytes.fromhex(match.group(0)).decode("utf-8", "strict")
        except (ValueError, UnicodeDecodeError):
            continue
        if _mostly_printable(decoded):
            found.append(decoded)
    return found


def _decode_escapes(text: str) -> str | None:
    r"""Resolve literal ``\uXXXX`` / ``\xNN`` escape sequences."""
    if "\\u" not in text and "\\x" not in text:
        return None
    try:
        decoded = codecs.decode(text, "unicode_escape")
    except (UnicodeDecodeError, ValueError):
        return None
    return decoded if decoded != text and _mostly_printable(decoded) else None


def normalized_variants(text: str) -> list[str]:
    """Return bounded alternate readings of ``text`` for detector matching.

    The original string is NOT included — callers already scan that. Returns at
    most :data:`MAX_VARIANTS` entries, each different from the input.
    """
    if not text or len(text) > MAX_INPUT:
        return []

    variants: list[str] = []
    seen = {text}

    def add(candidate: str | None) -> None:
        if (candidate and candidate not in seen and len(candidate) <= MAX_INPUT
                and len(variants) < MAX_VARIANTS):
            seen.add(candidate)
            variants.append(candidate)

    # 1. Strip invisible characters + NFKC-fold lookalikes (fullwidth, etc.).
    cleaned = _strip_invisible(text)
    folded = unicodedata.normalize("NFKC", cleaned)
    add(folded if folded != text else cleaned)

    # 2. Re-join deliberately separated tokens ("A K I A ..." / "s-k-_-l-i-v-e").
    add(_collapse_separators(folded))

    # 3. Literal escape sequences.
    add(_decode_escapes(text))

    # 4. Encoded payloads (base64 first — far more common in LLM output).
    for decoded in _decode_base64(folded):
        add(decoded)
    for decoded in _decode_hex(folded):
        add(decoded)

    return variants
