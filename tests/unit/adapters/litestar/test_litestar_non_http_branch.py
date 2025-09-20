# tests/unit/adapters/litestar/test_litestar_non_http_branch.py
import sys
import types

import pytest

# --- Lightweight stubs to avoid importing the real 'litestar' package ---
litestar_pkg = types.ModuleType("litestar")
litestar_middleware = types.ModuleType("litestar.middleware")
litestar_types = types.ModuleType("litestar.types")


class _AbstractMiddleware:
    def __init__(self, app, **kwargs):
        # Match the usage in RBACXMiddleware: super().__init__(app=app)
        self.app = app


# Provide just what's imported at runtime by rbacx.adapters.litestar
litestar_middleware.AbstractMiddleware = _AbstractMiddleware
litestar_types.Receive = object
litestar_types.Scope = object
litestar_types.Send = object

sys.modules["litestar"] = litestar_pkg
sys.modules["litestar.middleware"] = litestar_middleware
sys.modules["litestar.types"] = litestar_types
# ------------------------------------------------------------------------

from rbacx.adapters.litestar import RBACXMiddleware


@pytest.mark.asyncio
async def test_non_http_scope_passthrough_calls_next_app_and_returns():
    """
    Cover lines 31–32 in RBACXMiddleware.__call__:
      - await self.app(scope, receive, send)
      - return
    Triggered by a non-HTTP scope (e.g., 'websocket').
    """
    called = {"flag": False}

    async def downstream_app(scope, receive, send):
        called["flag"] = True  # should be reached for non-http

    async def receive():
        return {"type": "websocket.connect"}

    async def send(message):
        # not expected to be called on this path
        pass

    # Guard and build_env must not be used on this branch; fail if they are.
    class _Guard:
        async def evaluate_async(self, *a, **kw):
            raise AssertionError("evaluate_async must not be called for non-http scope")

    def _build_env(_scope):
        raise AssertionError("build_env must not be called for non-http scope")

    mw = RBACXMiddleware(downstream_app, guard=_Guard(), build_env=_build_env)

    scope = {"type": "websocket", "path": "/ws"}  # non-http → passthrough branch
    await mw(scope, receive, send)

    assert called["flag"] is True
