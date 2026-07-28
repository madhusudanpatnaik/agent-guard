"""DLP provider composition — regex core + optional ML + LLM-security.

The built-in :func:`~agentops.dlp.scanner.scan_payload` is the always-on core.
This module layers additional providers onto its result without changing any of
the scanner's callers:

* **LLM-guard** (on by default): prompt-injection / jailbreak / tool-abuse
  detectors from :mod:`agentops.dlp.llm_guard`.
* **Presidio** (opt-in via ``dlp_providers=["presidio"]``): Microsoft Presidio's
  ML/NLP entity recognizer for context-aware PII (names, locations, medical
  terms) that regex misses. Import-guarded — absence degrades to "regex only".

The merged result reuses the core's redacted payload (Presidio/LLM findings are
additive risk signals; the regex core already redacts the concrete secrets).
"""

from __future__ import annotations

import logging
from functools import lru_cache
from typing import Any

from ..config import get_settings
from . import llm_guard
from .scanner import DLPResult, scan_payload, scan_payload_custom

_log = logging.getLogger("agentops.dlp.providers")

# Presidio entity type -> (detector name, severity). Only a curated subset.
_PRESIDIO_ENTITIES = {
    "CREDIT_CARD": ("credit_card", "high"),
    "US_SSN": ("us_ssn", "high"),
    "US_PASSPORT": ("us_passport", "high"),
    "US_DRIVER_LICENSE": ("us_driver_license", "high"),
    "IBAN_CODE": ("iban", "high"),
    "MEDICAL_LICENSE": ("medical_license", "high"),
    "EMAIL_ADDRESS": ("email_address", "medium"),
    "PHONE_NUMBER": ("us_phone", "low"),
    "PERSON": ("person_name", "low"),
    "LOCATION": ("location", "low"),
    "IP_ADDRESS": ("ip_address", "low"),
}


@lru_cache
def _presidio_analyzer():
    """Build (and cache) a Presidio analyzer, or None if unavailable."""
    try:
        from presidio_analyzer import AnalyzerEngine
    except ImportError:
        _log.warning("dlp_providers includes 'presidio' but presidio-analyzer is not installed")
        return None
    try:
        return AnalyzerEngine()
    except Exception as exc:  # noqa: BLE001 — model load can fail
        _log.warning("Presidio analyzer failed to initialize: %s", exc)
        return None


def _presidio_findings(payload: Any):
    from .scanner import DLPFinding, _redact

    analyzer = _presidio_analyzer()
    if analyzer is None:
        return []
    findings = []

    def walk(node: Any, path: str) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                walk(v, f"{path}.{k}")
        elif isinstance(node, (list, tuple)):
            for i, v in enumerate(node):
                walk(v, f"{path}[{i}]")
        elif isinstance(node, str) and node.strip():
            try:
                results = analyzer.analyze(text=node, language="en")
            except Exception as exc:  # noqa: BLE001
                _log.warning("Presidio analyze failed: %s", exc)
                return
            for r in results:
                mapping = _PRESIDIO_ENTITIES.get(r.entity_type)
                if not mapping or r.score < 0.5:
                    continue
                name, severity = mapping
                findings.append(DLPFinding(
                    detector=f"ml_{name}", severity=severity, count=1,
                    sample=_redact(node[r.start:r.end]), path=path,
                ))

    walk(payload, "$")
    return findings


def scan_with_providers(payload: Any, custom_detectors: list[dict] | None = None) -> DLPResult:
    """Core regex scan (+ operator custom detectors) enriched with extra providers."""
    settings = get_settings()
    # The core pass includes the built-ins plus any org custom detectors, so a
    # custom hit both redacts the payload and counts toward blocking severity.
    result = scan_payload_custom(payload, custom_detectors) if custom_detectors \
        else scan_payload(payload)
    extra = list(result.findings)

    if settings.llm_guard_enabled:
        extra.extend(llm_guard.scan_payload_for_attacks(payload))

    if "presidio" in (settings.dlp_providers or []):
        extra.extend(_presidio_findings(payload))

    if len(extra) == len(result.findings):
        return result  # nothing added — return the core result unchanged

    # De-duplicate on (detector, path) so a provider echoing a regex hit doesn't
    # double-count, then rebuild the result preserving the core's redaction.
    seen: set[tuple[str, str]] = set()
    merged = []
    for f in extra:
        key = (f.detector, f.path)
        if key in seen:
            continue
        seen.add(key)
        merged.append(f)
    from .scanner import _SEVERITY_RANK

    merged.sort(key=lambda f: (-_SEVERITY_RANK.get(f.severity, 0), f.detector))
    return DLPResult(findings=merged, redacted=result.redacted)
