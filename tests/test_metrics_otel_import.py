import importlib
def test_otel_module_import():
    m = importlib.import_module("rbacx.metrics.otel")
    assert hasattr(m, "__dict__")
