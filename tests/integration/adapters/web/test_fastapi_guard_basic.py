
import types
from importlib import reload
import pytest

def test_fastapi_guard_noop_dependency():
    import rbacx.adapters.fastapi_guard as fg
    reload(fg)
    # Try several known entry points; skip if none present in this build
    for name in ("require", "require_access", "require_check"):
        fn = getattr(fg, name, None)
        if callable(fn):
            dep = fn()
            # Call with or without a dummy request; ignore result
            try:
                dep()
            except TypeError:
                class _Req: pass
                dep(_Req())
            return
    pytest.skip("No known dependency factory exposed in this build")
