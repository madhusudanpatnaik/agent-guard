"""Bounds on the optional ML DLP pass.

Presidio runs synchronously inside authorization, whose measured p50 is ~2.3ms,
while NLP entity recognition costs 20-80ms per string. An unbounded walk over a
payload tree therefore turns one governed decision into seconds of inference —
and since the gateway fails closed, a slow scan is an availability problem, not
merely a slow request.

These tests drive a **stub analyzer**, so they verify the guard rails (string
cap, per-string truncation, wall-clock budget, failure isolation) rather than
Presidio's detection accuracy, which is not benchmarked in this repository.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

import pytest

from agentops.config import get_settings
from agentops.dlp import providers


@dataclass
class _Result:
    entity_type: str
    start: int
    end: int
    score: float


class _StubAnalyzer:
    """Records every call; optionally sleeps to simulate inference latency."""

    def __init__(self, *, delay: float = 0.0, fail: bool = False):
        self.delay = delay
        self.fail = fail
        self.seen: list[str] = []

    def analyze(self, *, text: str, language: str):
        self.seen.append(text)
        if self.delay:
            time.sleep(self.delay)
        if self.fail:
            raise RuntimeError("model exploded")
        # Always "find" a person spanning the first 3 chars, if long enough.
        return [_Result("PERSON", 0, 3, 0.9)] if len(text) >= 3 else []


@pytest.fixture
def stub(monkeypatch):
    analyzer = _StubAnalyzer()
    monkeypatch.setattr(providers, "_presidio_analyzer", lambda: analyzer)
    return analyzer


@pytest.fixture(autouse=True)
def ml_settings(monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "dlp_providers", ["presidio"])
    monkeypatch.setattr(s, "dlp_ml_max_strings", 5)
    monkeypatch.setattr(s, "dlp_ml_max_string_chars", 20)
    monkeypatch.setattr(s, "dlp_ml_budget_ms", 250.0)
    return s


def test_caps_the_number_of_strings_analyzed(stub):
    payload = {f"k{i}": f"value number {i}" for i in range(50)}
    providers._presidio_findings(payload)
    assert len(stub.seen) == 5, "string cap not enforced — payload tree walked unbounded"


def test_truncates_long_strings_before_inference(stub):
    providers._presidio_findings({"big": "x" * 10_000})
    assert len(stub.seen) == 1
    assert len(stub.seen[0]) == 20, "oversized string sent to the model untruncated"


def test_wall_clock_budget_stops_the_pass(monkeypatch, ml_settings):
    # 20ms per string, 60ms budget, 100 strings: must stop early, not run all 100.
    analyzer = _StubAnalyzer(delay=0.02)
    monkeypatch.setattr(providers, "_presidio_analyzer", lambda: analyzer)
    monkeypatch.setattr(ml_settings, "dlp_ml_max_strings", 1000)
    monkeypatch.setattr(ml_settings, "dlp_ml_budget_ms", 60.0)

    started = time.monotonic()
    providers._presidio_findings({f"k{i}": f"string {i}" for i in range(100)})
    elapsed = time.monotonic() - started

    assert len(analyzer.seen) < 100, "budget ignored — every string was analyzed"
    # Allow one in-flight string past the deadline, plus scheduling slack.
    assert elapsed < 1.0, f"ML pass ran {elapsed:.2f}s despite a 60ms budget"


def test_analyzer_failure_does_not_abort_the_whole_scan(monkeypatch, ml_settings):
    analyzer = _StubAnalyzer(fail=True)
    monkeypatch.setattr(providers, "_presidio_analyzer", lambda: analyzer)
    findings = providers._presidio_findings({"a": "alpha", "b": "bravo"})
    assert findings == []
    assert len(analyzer.seen) == 2, "one bad string aborted the remaining scan"


def test_bounded_pass_is_logged_not_silent(stub, caplog):
    """A partial scan reported as a clean scan is how coverage gaps hide."""
    with caplog.at_level("WARNING", logger="agentops.dlp.providers"):
        providers._presidio_findings({f"k{i}": f"value {i}" for i in range(50)})
    assert any("ML DLP pass was bounded" in r.message for r in caplog.records)


def test_regex_core_still_redacts_when_ml_is_bounded(stub, ml_settings, monkeypatch):
    """Degrading to 'regex only' must not weaken the concrete-secret redaction."""
    monkeypatch.setattr(ml_settings, "dlp_ml_max_strings", 0)  # ML fully skipped
    payload = {"note": "key is AKIAIOSFODNN7EXAMPLE"}
    result = providers.scan_with_providers(payload)
    assert stub.seen == [], "ML ran despite a zero cap"
    assert "AKIAIOSFODNN7EXAMPLE" not in str(result.redacted)
    assert any(f.detector == "aws_access_key_id" for f in result.findings)
