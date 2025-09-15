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
    When OpenTelemetry SDK is not installed, importing the metrics module should not crash.
    We simulate missing package by removing 'opentelemetry.metrics' from sys.modules.
    """
    sys.modules.pop("opentelemetry.metrics", None)

    _purge("rbacx.metrics.otel")
    import rbacx.metrics.otel as otel

    importlib.reload(otel)

    # Constructing helper should not raise even if SDK is absent.
    _ = otel.OpenTelemetryMetrics()


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
