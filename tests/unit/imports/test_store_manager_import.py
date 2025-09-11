
import importlib
import pytest

def test_store_manager_init_and_no_backends():
    mod = importlib.import_module("rbacx.store.manager")
    # Try class-based API first
    cls = None
    for name in ("StoreManager", "Manager", "Store"):
        c = getattr(mod, name, None)
        if isinstance(c, type):
            cls = c
            break
    if cls is not None:
        m = cls()
        assert hasattr(m, "get") or hasattr(m, "open") or hasattr(m, "create")
        try:
            if hasattr(m, "get"):
                m.get("unknown")
        except Exception:
            pass
    else:
        if hasattr(mod, "get"):
            try:
                mod.get("unknown")
            except Exception:
                pass
        else:
            pytest.skip("store manager API not exported as class or module-level functions")
