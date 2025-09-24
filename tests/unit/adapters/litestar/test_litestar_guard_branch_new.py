import importlib
import pytest


import sys, types
def _install_min_litestar(monkeypatch=None):
    if "litestar.middleware" in sys.modules:
        return
    litestar_pkg = types.ModuleType("litestar")
    mw_mod = types.ModuleType("litestar.middleware")
    class AbstractMiddleware:
        def __init__(self, app, *args, **kwargs):
            self.app = app
        async def __call__(self, scope, receive, send):
            return await self.app(scope, receive, send)
    mw_mod.AbstractMiddleware = AbstractMiddleware
    sys.modules["litestar"] = litestar_pkg
    sys.modules["litestar.middleware"] = mw_mod

def test_litestar_guard_exports_require():
    try:
        m = importlib.import_module("rbacx.adapters.litestar_guard")
    except Exception:
        _install_min_litestar()
        m = importlib.import_module("rbacx.adapters.litestar_guard")
    assert hasattr(m, "require_access"), "litestar_guard must expose 'require_access'"
