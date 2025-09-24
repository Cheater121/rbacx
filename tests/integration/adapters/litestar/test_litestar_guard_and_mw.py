
import sys, types, pytest

# Provide minimal litestar stubs
conn_mod = types.ModuleType("litestar.connection")
class ASGIConnection: ...
conn_mod.ASGIConnection = ASGIConnection
sys.modules.setdefault("litestar.connection", conn_mod)

exc_mod = types.ModuleType("litestar.exceptions")
class PermissionDeniedException(Exception): ...
exc_mod.PermissionDeniedException = PermissionDeniedException
sys.modules.setdefault("litestar.exceptions", exc_mod)

def test_litestar_guard_checker_permit_and_deny():
    try:
        from rbacx.adapters.litestar_guard import require as ls_require
    except Exception:
        from rbacx.adapters.litestar_guard import require_access as ls_require
try:
    from rbacx.adapters.litestar_guard import require_access as ls_require
except Exception:
    pass
    # permit flow (protocol with is_allowed_sync)
    class G1:
        def is_allowed_sync(self, *a, **k): return True
    checker = ls_require("read", "doc", audit=False)
    checker(conn_mod.ASGIConnection(), G1())  # should not raise

    # deny flow
    class G2:
        def is_allowed_sync(self, *a, **k): return False
    checker2 = ls_require("write", "doc", audit=False)
    with pytest.raises(PermissionDeniedException):
        checker2(conn_mod.ASGIConnection(), G2())

    # audit=True -> no raise even if deny
    checker3 = ls_require("write", "doc", audit=True)
    checker3(conn_mod.ASGIConnection(), G2())
