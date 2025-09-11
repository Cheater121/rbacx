
import importlib
import sys
import types
import pytest

def _install_fake_prometheus(monkeypatch):
    class _Lbl:
        def __init__(self, obj):
            self._obj = obj
        def inc(self, *args, **kwargs):
            self._obj._count += 1
            return None
        def observe(self, v):
            self._obj._vals.append(float(v))
            return None

    class Cnt:
        def __init__(self, name, doc, labelnames=None, registry=None):
            self.name, self.doc = name, doc
            self.labelnames = tuple(labelnames or [])
            self._count = 0
        def labels(self, **kw):
            return _Lbl(self)

    class Hst:
        def __init__(self, name, doc, labelnames=None, registry=None):
            self.name, self.doc = name, doc
            self.labelnames = tuple(labelnames or [])
            self._vals = []
        def observe(self, v):
            self._vals.append(float(v))

    fake = types.ModuleType("prometheus_client")
    fake.Counter = Cnt
    fake.Histogram = Hst
    fake.REGISTRY = object()
    monkeypatch.setitem(sys.modules, "prometheus_client", fake)
    # reload rbacx wrapper to bind to stub
    if "rbacx.metrics.prometheus" in sys.modules:
        importlib.reload(sys.modules["rbacx.metrics.prometheus"])

def _install_fake_otel(monkeypatch):
    class _Hist:
        def __init__(self): self._vals = []
        def record(self, v): self._vals.append(float(v))

    class _Counter:
        def __init__(self): self._count = 0
        def add(self, v, attributes=None): self._count += int(v)

    class _Meter:
        def create_counter(self, name, **kw): return _Counter()
        def create_histogram(self, name, **kw): return _Hist()

    def get_meter(*args, **kwargs): return _Meter()

    fake = types.ModuleType("opentelemetry.metrics")
    fake.get_meter = get_meter
    monkeypatch.setitem(sys.modules, "opentelemetry.metrics", fake)
    if "rbacx.metrics.otel" in sys.modules:
        importlib.reload(sys.modules["rbacx.metrics.otel"])

def test_prom_metrics_inc_and_observe(monkeypatch):
    _install_fake_prometheus(monkeypatch)
    from rbacx.metrics.prometheus import PrometheusMetrics
    m = PrometheusMetrics(namespace="rbacx_test")
    m.inc("rbacx_decisions_total", {"allowed":"true","reason":"ok"})
    if hasattr(m, "observe"):
        m.observe("rbacx_decision_duration_seconds", 0.125)

def test_otel_metrics_inc_and_observe(monkeypatch):
    _install_fake_otel(monkeypatch)
    from rbacx.metrics.otel import OpenTelemetryMetrics
    m = OpenTelemetryMetrics()
    m.inc("rbacx_decisions_total", {"allowed":"true","reason":"ok"})
    if hasattr(m, "observe"):
        m.observe("rbacx_decision_seconds", 0.2)
    else:
        pytest.skip("OpenTelemetryMetrics.observe() not available")
