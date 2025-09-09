import importlib, pytest
def test_starlette_adapter_import():
    try:
        importlib.import_module("rbacx.adapters.starlette")
    except Exception:
        pytest.xfail("starlette not installed")
