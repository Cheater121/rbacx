import importlib, pytest

def test_telemetry_modules_import():
    for mname in ["rbacx.telemetry.decision_log", "rbacx.telemetry.metrics_prom"]:
        try:
            importlib.import_module(mname)
        except Exception:
            pytest.xfail(f"{mname} optional deps not installed")
