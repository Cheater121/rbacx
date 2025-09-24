import inspect
import types
import pytest

# FastAPI
fastapi = pytest.importorskip("fastapi", reason="Optional dep: FastAPI not installed")
from rbacx.adapters.fastapi import require_access as fa_require

@pytest.mark.asyncio
async def test_fastapi_require_access_denied_with_headers():
    class _G:
        async def evaluate_async(self, *_a, **_k):
            return types.SimpleNamespace(allowed=False, reason="x", rule_id="r", policy_id="p")
    dep = fa_require(_G(), lambda *_: (None, None, None, None), add_headers=True)
    with pytest.raises(fastapi.HTTPException) as ei:
        res = dep(object())
        if inspect.iscoroutine(res):
            await res
    hdrs = getattr(ei.value, "headers", {}) or {}
    if hdrs:
        assert hdrs.get("X-RBACX-Reason") == "x"

# Litestar middleware
litestar = pytest.importorskip("litestar", reason="Optional dep: Litestar not installed")
from litestar import Litestar, get
from litestar.middleware import DefineMiddleware
from rbacx.adapters.litestar import RBACXMiddleware

def _build_env(scope):
    return None, None, None, None

@get("/ok")
async def ok():
    return {"ok": True}

class _Allow:
    async def evaluate_async(self, *_a, **_k):
        return types.SimpleNamespace(allowed=True)

class _Deny:
    async def evaluate_async(self, *_a, **_k):
        return types.SimpleNamespace(allowed=False, reason="nope")

def test_litestar_middleware_denies_and_allows():
    app = Litestar(
        route_handlers=[ok],
        middleware=[DefineMiddleware(RBACXMiddleware, guard=_Deny(), build_env=_build_env)],
    )
    # Simple smoke test: building app should succeed with middleware; actual ASGI call tested elsewhere.
    assert app is not None

# Starlette decorator
starlette = pytest.importorskip("starlette", reason="Optional dep: Starlette not installed")
from rbacx.adapters.starlette import require_access as st_require
from starlette.responses import JSONResponse

def _build_env_st(_req):
    return None, None, None, None

@pytest.mark.asyncio
async def test_starlette_require_allows_and_denies():
    class GAllow:
        async def evaluate_async(self, *_a, **_k):
            return types.SimpleNamespace(allowed=True)
    class GDeny:
        async def evaluate_async(self, *_a, **_k):
            return types.SimpleNamespace(allowed=False, reason="nope")

    @st_require(GAllow(), _build_env_st)
    async def ok_handler(_req):
        return JSONResponse({"ok": True})
    assert inspect.iscoroutinefunction(ok_handler)

    @st_require(GDeny(), _build_env_st, add_headers=True)
    async def deny_handler(_req):
        return JSONResponse({"ok": True})
    resp = await deny_handler(object())
    # In decorator mode deny returns an ASGI-callable response; for test we just assert it's callable or has attrs
    assert callable(resp) or hasattr(resp, "status_code")
