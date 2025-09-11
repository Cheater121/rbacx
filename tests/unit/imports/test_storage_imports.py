import importlib
def test_storage_init_import():
    m = importlib.import_module("rbacx.storage")
    assert hasattr(m, "__dict__")
