
import sys, types
import importlib
import pytest

def _install_fake_prometheus(monkeypatch):
    class _Lbl:
        def __init__(self, obj): self._obj = obj
        def inc(self): self._obj._count += 1
    class Counter:
        def __init__(self, name, doc, labelnames=None):
            self._count = 0
            self.labelnames = tuple(labelnames or [])
        def labels(self, **kw): return _Lbl(self)
    fake = types.ModuleType("prometheus_client")
    fake.Counter = Counter
    monkeypatch.setitem(sys.modules, "prometheus_client", fake)
    return fake

def test_prometheus_metrics_sink_increments(monkeypatch):
    _install_fake_prometheus(monkeypatch)
    import importlib
    import rbacx.telemetry.metrics_prom as mp
    importlib.reload(mp)
    from rbacx.telemetry.metrics_prom import PrometheusMetricsSink
    m = PrometheusMetricsSink()
    m.inc("rbacx_decision_total", {"effect":"permit","allowed":"true","rule_id":"r1"})
