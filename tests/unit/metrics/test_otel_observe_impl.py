import builtins
import importlib
import sys
import types


def _purge(modname: str) -> None:
    for k in list(sys.modules):
        if k == modname or k.startswith(modname + "."):
            sys.modules.pop(k, None)


def test_otel_observe_no_sdk(monkeypatch):
    """Test that observe() safely no-ops when opentelemetry.metrics is unavailable."""
    _purge("rbacx.metrics.otel")

    real_import = builtins.__import__

    def fake_import(name, *a, **k):
        if name == "opentelemetry.metrics":
            raise ImportError("not installed")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    import rbacx.metrics.otel as otel

    importlib.reload(otel)

    m = otel.OpenTelemetryMetrics()
    # No SDK -> histogram not created
    assert getattr(m, "_hist", None) is None
    # Should not raise
    m.observe("rbacx_decision_seconds", 0.321, {"decision": "deny"})
    m.inc("rbacx_decisions_total", {"decision": "deny"})


def test_otel_observe_record_called(monkeypatch):
    """Test that observe() calls Histogram.record with attributes when available."""
    _purge("rbacx.metrics.otel")

    calls = {"record": [], "add": []}

    class _Counter:
        def add(self, value, attributes=None):
            calls["add"].append((value, dict(attributes or {})))

    class _Hist:
        def record(self, value, attributes=None):
            calls["record"].append((float(value), dict(attributes or {})))

    class _Meter:
        def create_counter(self, *a, **k):
            return _Counter()

        def create_histogram(self, *a, **k):
            return _Hist()

    fake = types.ModuleType("opentelemetry.metrics")
    fake.get_meter = lambda *a, **k: _Meter()
    monkeypatch.setitem(sys.modules, "opentelemetry.metrics", fake)

    import rbacx.metrics.otel as otel

    importlib.reload(otel)

    m = otel.OpenTelemetryMetrics()
    m.inc("rbacx_decisions_total", {"decision": "permit"})
    m.observe("rbacx_decision_seconds", 0.42, {"decision": "permit"})

    assert calls["add"] == [(1, {"decision": "permit"})]
    assert calls["record"] == [(0.42, {"decision": "permit"})]
