
import types, sys
from importlib import reload

def test_otel_inc_only(monkeypatch):
    # Provide minimal otel stub if not present
    if "opentelemetry.metrics" not in sys.modules:
        class _Hist:
            def record(self, v): pass
        class _Counter:
            def add(self, v, attributes=None): pass
        class _Meter:
            def create_counter(self, *a, **k): return _Counter()
            def create_histogram(self, *a, **k): return _Hist()
        def get_meter(*a, **k): return _Meter()
        mod = types.ModuleType("opentelemetry.metrics")
        mod.get_meter = get_meter
        sys.modules["opentelemetry.metrics"] = mod
    import rbacx.metrics.otel as m
    reload(m)
    o = m.OpenTelemetryMetrics()
    o.inc("rbacx_decisions_total", {"allowed":"true","reason":"ok"})
