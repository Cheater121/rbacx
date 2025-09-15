import importlib
import sys
import types

import pytest


def _purge(prefix: str) -> None:
    """Drop all modules that start with the given prefix from sys.modules."""
    for k in list(sys.modules):
        if k.startswith(prefix):
            sys.modules.pop(k, None)


def test_otel_no_sdk_is_noop(monkeypatch):
    """
    This test must pass in both environments:

    1) opentelemetry-api is NOT installed:
       The adapter raises RuntimeError on construction, which we assert.

    2) opentelemetry-api is installed but no SDK is configured:
       Per OpenTelemetry API semantics, a no-op meter is returned, so our wrapper
       constructs successfully and its methods are safe no-ops (no exceptions).
    """
    _purge("rbacx.metrics.otel")

    # Detect if the OpenTelemetry API package is importable on this runner.
    try:
        import opentelemetry.metrics  # noqa: F401
        api_present = True
    except Exception:
        api_present = False

    import rbacx.metrics.otel as otel
    importlib.reload(otel)

    if not api_present:
        # API is missing: adapter signals the optional dependency clearly.
        with pytest.raises(RuntimeError):
            otel.OpenTelemetryMetrics()
        return

    # API is present (SDK may or may not be configured). Construction and calls
    # should be no-ops and must not raise.
    m = otel.OpenTelemetryMetrics()
    m.inc("rbacx.decisions", labels={"path": "/", "method": "GET"})
    m.observe("rbacx.decision.time", 12.5, labels={"path": "/", "method": "GET"})

    # If we got here, the no-op path worked fine.
    assert True


def test_otel_instrument_creation_failure_is_handled(monkeypatch):
    """
    Current library behavior: if create_counter/create_histogram fails inside __init__,
    the error is propagated. We assert this explicitly (rather than expecting a silent no-op).
    """

    class _Meter:
        def create_counter(self, *a, **k):
            raise RuntimeError("no counter")

        def create_histogram(self, *a, **k):
            raise RuntimeError("no histogram")

    fake = types.ModuleType("opentelemetry.metrics")
    fake.get_meter = lambda *a, **k: _Meter()
    monkeypatch.setitem(sys.modules, "opentelemetry.metrics", fake)

    _purge("rbacx.metrics.otel")
    import rbacx.metrics.otel as otel

    importlib.reload(otel)

    with pytest.raises(RuntimeError):
        _ = otel.OpenTelemetryMetrics()
