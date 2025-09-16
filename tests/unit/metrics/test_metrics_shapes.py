import pytest


def test_prometheus_sink_importable():
    try:
        from rbacx.metrics.prometheus import PrometheusMetrics
    except Exception:
        pytest.skip("prometheus_client not installed")
    m = None
    try:
        m = PrometheusMetrics()  # may raise if no client
    except RuntimeError:
        pytest.skip("prometheus_client not installed")
    # inc shouldn't raise
    m.inc("rbacx_decisions_total", labels={"decision": "allow"})


def test_otlp_sink_importable():
    try:
        from rbacx.metrics.otel import OpenTelemetryMetrics
    except Exception:
        pytest.skip("opentelemetry-api not installed")
    try:
        m = OpenTelemetryMetrics()
    except RuntimeError:
        pytest.skip("opentelemetry-api not installed")
    m.inc("rbacx_decisions_total", labels={"decision": "allow"})
