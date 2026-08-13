"""Structured (JSON-lines) logging setup.

The audit, access, and background loggers already emit JSON payloads as their
message; this attaches a single stdout handler under the ``agentguard`` namespace
so every line is a self-contained JSON object, ready to ship to a SIEM or log
aggregator. Idempotent and safe to call more than once.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone


class JsonLineFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        msg = record.getMessage()
        entry: dict = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
        }
        # If the message is itself a JSON object (audit/access events), nest it;
        # otherwise carry it as a plain string.
        stripped = msg.lstrip()
        if stripped.startswith("{"):
            try:
                entry["event"] = json.loads(stripped)
            except ValueError:
                entry["message"] = msg
        else:
            entry["message"] = msg
        if record.exc_info:
            entry["exc"] = self.formatException(record.exc_info)
        return json.dumps(entry, default=str)


def configure_logging(level: str = "INFO", as_json: bool = True) -> None:
    logger = logging.getLogger("agentguard")
    if getattr(logger, "_agentguard_configured", False):
        return
    handler = logging.StreamHandler(sys.stdout)
    if as_json:
        handler.setFormatter(JsonLineFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s [%(name)s] %(levelname)s %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(level.upper())
    logger.propagate = False
    logger._agentguard_configured = True  # type: ignore[attr-defined]
