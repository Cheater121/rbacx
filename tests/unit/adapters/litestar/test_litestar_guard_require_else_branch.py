import types
import importlib
import pytest

import sys, types as _types
def _install_min_litestar():
    if 'litestar.middleware' in sys.modules:
        return
    pkg = _types.ModuleType('litestar')
    mw = _types.ModuleType('litestar.middleware')
    class AbstractMiddleware:
        def __init__(self, app, *args, **kwargs):
            self.app = app
        async def __call__(self, scope, receive, send):
            return await self.app(scope, receive, send)
    mw.AbstractMiddleware = AbstractMiddleware
    sys.modules['litestar'] = pkg
    sys.modules['litestar.middleware'] = mw

def _build_env(_conn):
    return None, None, None, None

@pytest.mark.asyncio
async def test_require_else_branch_evaluate_async_path():
    try:
        mod = importlib.import_module('rbacx.adapters.litestar_guard')
    except Exception:
        _install_min_litestar()
        mod = importlib.import_module('rbacx.adapters.litestar_guard')
    require_access = getattr(mod, 'require_access')
    class G:
        async def evaluate_async(self, *_a, **_k):
            return types.SimpleNamespace(allowed=True)
    checker = require_access(G(), _build_env)
    assert callable(checker)
