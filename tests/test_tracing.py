"""Tests for the optional OpenTelemetry tracing shim (no-op path)."""

from agentops import tracing
from agentops.config import get_settings


def test_span_is_noop_when_inactive():
    tracing._reset_for_tests()
    assert tracing.is_active() is False
    # Using a span must not raise and must run the body.
    ran = []
    with tracing.span("test.span", **{"k": "v", "n": 1, "none": None}):
        ran.append(True)
    assert ran == [True]


def test_inject_context_noop_returns_headers_unchanged():
    tracing._reset_for_tests()
    headers = {"X-API-Key": "abc"}
    out = tracing.inject_context(headers)
    assert out == {"X-API-Key": "abc"}
    assert "traceparent" not in out  # no propagator active


def test_configure_tracing_disabled_by_default():
    tracing._reset_for_tests()
    assert tracing.configure_tracing() is False
    assert tracing.is_active() is False


def test_configure_tracing_when_enabled_is_consistent(monkeypatch):
    # Enabled: returns True iff the OTel SDK is importable, never raises, and the
    # return value always matches is_active(). (False in the default install
    # where OTel is absent; True once the [otel] extra is present.)
    monkeypatch.setattr(get_settings(), "otel_enabled", True)
    tracing._reset_for_tests()
    active = tracing.configure_tracing()
    assert isinstance(active, bool)
    assert active == tracing.is_active()
    tracing._reset_for_tests()


def test_gateway_authorize_works_with_tracing_shim(client, admin_headers):
    """The span wrapper around authorize must not change behavior when inactive."""
    tracing._reset_for_tests()
    role = client.post("/api/roles", json={"name": "t"}, headers=admin_headers).json()
    client.post(f"/api/roles/{role['id']}/policies", headers=admin_headers, json={
        "effect": "allow", "resource": "db:x", "actions": ["read"]})
    agent = client.post("/api/agents", json={"name": "TB", "role_id": role["id"]},
                        headers=admin_headers).json()
    r = client.post("/api/v1/gateway/authorize", headers={"X-API-Key": agent["api_key"]},
                    json={"action_type": "read", "resource": "db:x"}).json()
    assert r["decision"] == "allow"


# --- real OTel path (only runs when the SDK is installed) -------------------

def test_real_otel_spans_are_recorded(monkeypatch):
    """When OTel is installed + enabled, span() actually records spans.

    Skipped in the default install (SDK absent); proves the non-no-op path
    without needing an external collector by using an in-memory exporter.
    """
    import pytest
    pytest.importorskip("opentelemetry.sdk.trace")

    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    # Point the tracing module at our provider directly.
    tracing._reset_for_tests()
    tracing._tracer = provider.get_tracer("agentops-test")

    with tracing.span("unit.work", **{"agentops.k": "v"}):
        pass

    spans = exporter.get_finished_spans()
    assert any(s.name == "unit.work" for s in spans)
    recorded = next(s for s in spans if s.name == "unit.work")
    assert recorded.attributes.get("agentops.k") == "v"
    tracing._reset_for_tests()


def test_inject_context_adds_traceparent_with_real_propagator():
    import pytest
    pytest.importorskip("opentelemetry.propagate")
    from opentelemetry.propagate import get_global_textmap
    from opentelemetry.sdk.trace import TracerProvider

    tracing._reset_for_tests()
    provider = TracerProvider()
    tracing._tracer = provider.get_tracer("agentops-test")
    tracing._propagator = get_global_textmap()
    with tracing.span("outer"):
        headers = tracing.inject_context({})
    # Inside an active span the W3C traceparent header is injected.
    assert "traceparent" in headers
    tracing._reset_for_tests()
