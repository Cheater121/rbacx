import importlib

def test_prometheus_module_import():
    m = importlib.import_module("rbacx.metrics.prometheus")
    assert hasattr(m, "__dict__")
