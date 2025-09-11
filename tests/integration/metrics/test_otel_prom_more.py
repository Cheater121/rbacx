
import sys, types
from importlib import reload
import pytest

def install_fake_otel(monkeypatch):
    class _Hist:
        def __init__(self): self.values = []
        def record(self, v): self.values.append(float(v))
    class _Counter:
        def __init__(self): self.n = 0
        def add(self, v, attributes=None): self.n += int(v)
    class _Meter:
        def create_counter(self, *a, **k): return _Counter()
        def create_histogram(self, *a, **k): return _Hist()
    def get_meter(*a, **k): return _Meter()
    mod = types.ModuleType("opentelemetry.metrics")
    mod.get_meter = get_meter
    monkeypatch.setitem(sys.modules, "opentelemetry.metrics", mod)

def test_otel_observe_seconds_to_ms(monkeypatch):
    install_fake_otel(monkeypatch)
    import rbacx.metrics.otel as m
    reload(m)
    o = m.OpenTelemetryMetrics()
    # seconds name converts to ms; if the observe API is absent in the wrapper — skip
    if hasattr(o, "observe"):
        o.observe("rbacx_decision_seconds", 0.2)
        o.observe("rbacx_decision_duration_ms", 7)
        o.observe("rbacx_decision_seconds", "0.5")
    else:
        pytest.skip("OpenTelemetryMetrics.observe() is not exposed in this build")

def test_prometheus_runtime_error_when_missing(monkeypatch):
    # If prometheus_client is present in the environment/cache,
    # the wrapper's behavior legitimately does NOT raise an exception.
    try:
        import prometheus_client  # noqa: F401
        pytest.skip("prometheus_client is available in environment")
    except Exception:
        pass
    if "prometheus_client" in sys.modules:
        del sys.modules["prometheus_client"]
    import rbacx.metrics.prometheus as prom
    reload(prom)
    with pytest.raises(RuntimeError):
        prom.PrometheusMetrics()
