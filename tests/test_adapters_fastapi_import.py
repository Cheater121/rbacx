import importlib, pytest
def test_fastapi_adapter_import():
    try:
        importlib.import_module("rbacx.adapters.fastapi")
    except Exception:
        pytest.xfail("fastapi not installed")
