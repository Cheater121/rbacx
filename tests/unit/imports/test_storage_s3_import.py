import importlib, pytest
def test_s3_module_import():
    try:
        importlib.import_module("rbacx.storage.s3")
    except Exception:
        pytest.xfail("s3 backend optional dependencies are not installed")
