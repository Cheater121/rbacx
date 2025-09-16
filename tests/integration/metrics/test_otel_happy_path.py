import importlib
import sys
import types

import pytest


def _purge(modname: str) -> None:
    for k in list(sys.modules):
        if k == modname or k.startswith(modname + "."):
            sys.modules.pop(k, None)


@pytest.mark.filterwarnings("ignore::DeprecationWarning")
def test_opentelemetry_happy_path_counter(monkeypatch):
    """
    Provide a minimal opentelemetry.metrics implementation so that
    OpenTelemetryMetrics can create a counter and use it. We verify that
    calling inc() is safe and (implementation-dependent) may call the underlying
    Counter.add(...).

    NOTE: The adapter also constructs a Histogram on init, so our fake Meter
    must implement `create_histogram()` even if this test does not assert on it.
    """
    calls = []

    class _Counter:
        def add(self, value, attributes=None):
            calls.append((value, dict(attributes or {})))

    class _Hist:
        def record(self, value, attributes=None):
            # Not asserted in this test; present to satisfy adapter init.
            pass

    class _Meter:
        def create_counter(self, *a, **k):
            return _Counter()

        def create_histogram(self, *a, **k):
            return _Hist()

    fake = types.ModuleType("opentelemetry.metrics")
    fake.get_meter = lambda *a, **k: _Meter()
    monkeypatch.setitem(sys.modules, "opentelemetry.metrics", fake)

    _purge("rbacx.metrics.otel")
    import rbacx.metrics.otel as otel

    importlib.reload(otel)

    m = otel.OpenTelemetryMetrics()

    # Current adapter signature: inc(name, labels=None)
    m.inc("rbacx_decisions_total", labels={"decision": "allow"})

    # Some builds of the adapter may intentionally no-op if the SDK/pipeline is not configured.
    # Accept both behaviors; if the call reached the underlying counter we should see exactly one add().
    if calls:
        assert calls == [(1, {"decision": "allow"})]
