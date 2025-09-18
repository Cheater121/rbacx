import sys
import types
from importlib import reload

import pytest


# ---- OTEL fake metrics (aligned with implementation in src/rbacx/metrics/otel.py) ----
def install_fake_otel(monkeypatch):
    class _Hist:
        def __init__(self):
            self.values = []

        def record(self, v, *, attributes=None):
            # record(float) is used by the implementation; attributes is accepted and ignored in fake
            self.values.append(float(v))

    class _Counter:
        def __init__(self):
            self.values = []

        def add(self, n, *, attributes=None):
            # add(int) is used by the implementation; attributes is accepted and ignored in fake
            self.values.append(int(n))

    class _Meter:
        def __init__(self):
            self.hist = _Hist()
            self.cnt = _Counter()

        def create_histogram(self, *_a, **_k):
            return self.hist

        def create_counter(self, *_a, **_k):
            return self.cnt

    # Fake 'opentelemetry.metrics' module with get_meter() as used by the code
    otel_pkg = types.ModuleType("opentelemetry")
    metrics_mod = types.ModuleType("opentelemetry.metrics")

    def get_meter(*_a, **_k):
        return _Meter()

    metrics_mod.get_meter = get_meter  # what rbacx.metrics.otel imports
    monkeypatch.setitem(sys.modules, "opentelemetry", otel_pkg)
    monkeypatch.setitem(sys.modules, "opentelemetry.metrics", metrics_mod)


def test_otel_histogram_and_counter(monkeypatch):
    install_fake_otel(monkeypatch)
    import rbacx.metrics.otel as otel

    reload(otel)
    # Class name in implementation is OpenTelemetryMetrics
    m = otel.OpenTelemetryMetrics()
    m.observe("rbacx_decision_seconds", 0.12, {"decision": "permit"})
    m.inc("rbacx_decisions_total", {"decision": "permit"})


# ---- Prometheus: run when client is installed ----
prometheus_client = pytest.importorskip(
    "prometheus_client",
    exc_type=ImportError,
    reason="Optional dep: prometheus_client not installed",
)


def test_prometheus_metrics_present_path():
    import rbacx.metrics.prometheus as prom

    reload(prom)
    m = prom.PrometheusMetrics()
    m.inc("rbacx_decisions_total", {"decision": "permit"})
    if hasattr(m, "observe"):
        m.observe("rbacx_decision_seconds", 0.1, {"decision": "permit"})
