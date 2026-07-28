"""OpenTelemetry tracing — end-to-end spans across the governance pipeline.

Prometheus metrics and the SIEM webhook answer "how many / what happened";
distributed tracing answers "where did the latency go" across
Agent → Proxy → Control Plane → Upstream. This module wires OpenTelemetry in
*optionally*: with ``otel_enabled=false`` (default) or the OTel packages
absent, :func:`span` is a zero-overhead no-op and nothing else in the codebase
needs to change. When enabled, spans are exported via OTLP and W3C
``traceparent`` context is propagated to upstream calls so a single trace spans
the whole chain.
"""

from __future__ import annotations

import logging
from contextlib import contextmanager
from typing import Any, Iterator

_log = logging.getLogger("agentops.tracing")

_tracer: Any = None  # set by configure_tracing() when OTel is active
_propagator: Any = None


def configure_tracing() -> bool:
    """Initialize OTel if enabled and installed. Returns True when active."""
    global _tracer, _propagator
    from .config import get_settings

    settings = get_settings()
    if not settings.otel_enabled:
        return False
    try:
        from opentelemetry import trace
        from opentelemetry.propagate import get_global_textmap
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError:
        _log.warning("otel_enabled=true but opentelemetry packages are not installed; "
                     "tracing disabled")
        return False

    resource = Resource.create({"service.name": settings.otel_service_name})
    provider = TracerProvider(resource=resource)
    try:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
            OTLPSpanExporter,
        )

        endpoint = settings.otel_exporter_otlp_endpoint or None
        provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint)))
    except ImportError:
        _log.warning("OTLP exporter not installed; spans will not be exported")
    trace.set_tracer_provider(provider)
    _tracer = trace.get_tracer("agentops")
    _propagator = get_global_textmap()
    _log.info("OpenTelemetry tracing enabled (service=%s)", settings.otel_service_name)
    return True


@contextmanager
def span(name: str, **attributes: Any) -> Iterator[None]:
    """Start a span with attributes, or a no-op if tracing is inactive."""
    if _tracer is None:
        yield
        return
    with _tracer.start_as_current_span(name) as sp:
        for k, v in attributes.items():
            if v is not None:
                try:
                    sp.set_attribute(k, v)
                except Exception:  # noqa: BLE001 — never let telemetry raise
                    pass
        yield


def inject_context(headers: dict[str, str]) -> dict[str, str]:
    """Inject W3C trace context into outbound headers (no-op when inactive)."""
    if _propagator is None:
        return headers
    try:
        _propagator.inject(headers)
    except Exception:  # noqa: BLE001
        pass
    return headers


def is_active() -> bool:
    return _tracer is not None


def _reset_for_tests() -> None:
    global _tracer, _propagator
    _tracer = None
    _propagator = None
