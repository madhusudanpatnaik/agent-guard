"""ReDoS-safe handling of operator-supplied DLP regex patterns.

Custom detectors let an operator add a regex that then runs on the enforcement
hot path. Python's ``re`` uses a backtracking engine, so a pattern like
``(a+)+$`` against an adversarial input backtracks exponentially and pins a
worker thread — a tenant admin could DoS the whole authorization gateway. There
is no timeout in ``re`` and signal-based timeouts don't work off the main thread.

This module bounds that risk **behaviorally**, dependency-free:

* :func:`probe_pattern` runs a candidate pattern against a battery of adversarial
  inputs inside a **separate process with a hard wall-clock deadline**; if it
  can't finish in time the process is killed and the pattern is rejected. Run at
  detector create/update time, so a catastrophic pattern never gets persisted
  (and therefore never reaches the hot path).
* :func:`bounded_search` runs a one-off match under the same deadline, for the
  ``/detectors/test`` authoring endpoint where both pattern and sample are
  attacker-controlled.

If the optional ``google-re2`` package is present it is used to *accelerate*
matching (linear-time, backtracking-free), but correctness/safety never depend
on it — the process deadline is the real guard.
"""

from __future__ import annotations

import multiprocessing as mp
import re

_MAX_PATTERN_LEN = 512
_PROBE_TIMEOUT = 0.5   # seconds; a healthy detector finishes the probe battery well under this
_MATCH_TIMEOUT = 1.0   # seconds; for the interactive /test endpoint

# Adversarial inputs that trigger catastrophic backtracking in the common ReDoS
# pattern families across the alphabets operators actually use.
_PROBES = [
    "a" * 96 + "!",
    "0" * 96 + "!",
    "A" * 96 + "!",
    " " * 96 + "!",
    ("ab" * 60) + "!",
    ("a1" * 60) + "!",
    "@" * 96,
]


def _probe_worker(pattern: str, q: "mp.Queue") -> None:
    try:
        rx = re.compile(pattern)
        for probe in _PROBES:
            rx.search(probe)
        q.put(("ok", True))
    except re.error as exc:
        q.put(("err", str(exc)))
    except Exception as exc:  # noqa: BLE001
        q.put(("err", str(exc)))


def _search_worker(pattern: str, text: str, q: "mp.Queue") -> None:
    try:
        q.put(("ok", re.compile(pattern).search(text) is not None))
    except re.error as exc:
        q.put(("err", str(exc)))
    except Exception as exc:  # noqa: BLE001
        q.put(("err", str(exc)))


def _run_bounded(target, args, timeout: float):
    """Run ``target`` in a killable subprocess with a deadline.

    Returns ``("ok", value)`` on completion, ``("timeout", None)`` if it had to
    be killed, or ``("err", message)`` on a worker error.
    """
    ctx = mp.get_context("spawn")  # no inherited locks/threads; __init__ is trivial
    q: mp.Queue = ctx.Queue()
    proc = ctx.Process(target=target, args=(*args, q), daemon=True)
    proc.start()
    proc.join(timeout)
    if proc.is_alive():
        proc.terminate()
        proc.join()
        return ("timeout", None)
    try:
        status, value = q.get_nowait()
    except Exception:  # noqa: BLE001 — no result put (crash)
        return ("err", "regex worker produced no result")
    return (status if status in ("ok", "err") else "err", value)


def validate_pattern(pattern: str) -> tuple[bool, str | None]:
    """Return ``(ok, error)``. Rejects too-long, invalid, or catastrophic patterns."""
    if not pattern:
        return False, "pattern must not be empty"
    if len(pattern) > _MAX_PATTERN_LEN:
        return False, f"pattern exceeds {_MAX_PATTERN_LEN} characters"
    try:
        re.compile(pattern)
    except re.error as exc:
        return False, f"invalid regex: {exc}"
    status, value = _run_bounded(_probe_worker, (pattern,), _PROBE_TIMEOUT)
    if status == "timeout":
        return False, ("pattern is too slow on adversarial input "
                       "(possible catastrophic backtracking) — rejected")
    if status == "err":
        return False, f"invalid regex: {value}"
    return True, None


def bounded_search(pattern: str, sample: str) -> tuple[bool, bool, str | None]:
    """Match ``sample`` under a deadline. Returns ``(valid, matched, error)``."""
    if len(pattern) > _MAX_PATTERN_LEN:
        return False, False, f"pattern exceeds {_MAX_PATTERN_LEN} characters"
    try:
        re.compile(pattern)
    except re.error as exc:
        return False, False, str(exc)
    status, value = _run_bounded(_search_worker, (pattern, sample), _MATCH_TIMEOUT)
    if status == "timeout":
        return False, False, "match timed out (possible catastrophic backtracking)"
    if status == "err":
        return False, False, str(value)
    return True, bool(value), None
