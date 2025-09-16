import builtins
import importlib
import sys
import types


def _purge(modname: str) -> None:
    for k in list(sys.modules):
        if k == modname or k.startswith(modname + "."):
            sys.modules.pop(k, None)


def test_prometheus_observe_no_sdk(monkeypatch):
    """Test that observe() safely no-ops when prometheus_client is unavailable."""
    _purge("rbacx.metrics.prometheus")

    real_import = builtins.__import__

    def fake_import(name, *a, **k):
        if name == "prometheus_client":
            raise ImportError("not installed")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    import rbacx.metrics.prometheus as prom

    importlib.reload(prom)

    m = prom.PrometheusMetrics()
    # Histogram is not created -> observe should be a safe no-op
    assert getattr(m, "_hist", None) is None
    m.observe("rbacx_decision_seconds", 0.123, {"decision": "permit"})
    # Counter may also be None in this case; inc() should also be safe
    m.inc("rbacx_decisions_total", {"decision": "permit"})


def test_prometheus_observe_record_called(monkeypatch):
    """Test that observe() records to Histogram when available."""
    _purge("rbacx.metrics.prometheus")

    class _Counter:
        def __init__(self, *a, **k):
            self.calls = []

        class _Child:
            def __init__(self, parent, labels):
                self.parent = parent
                self.labels = labels

            def inc(self, *a, **k):
                self.parent.calls.append(("inc", dict(self.labels)))

        def labels(self, **labels):
            return self._Child(self, labels)

    class _Histogram:
        def __init__(self, *a, **k):
            self.values = []

        def observe(self, v):
            self.values.append(float(v))

    fake = types.ModuleType("prometheus_client")
    fake.Counter = _Counter
    fake.Histogram = _Histogram
    monkeypatch.setitem(sys.modules, "prometheus_client", fake)

    import rbacx.metrics.prometheus as prom

    importlib.reload(prom)

    m = prom.PrometheusMetrics()
    # inc path with labels
    m.inc("rbacx_decisions_total", {"decision": "permit"})
    assert getattr(m._counter, "calls", []) == [("inc", {"decision": "permit"})]

    # observe path
    m.observe("rbacx_decision_seconds", 0.5, {"decision": "permit"})
    assert getattr(m._hist, "values", []) == [0.5]
