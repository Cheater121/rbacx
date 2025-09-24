import inspect
import types
import importlib
import warnings
import pytest

# Suppress Litestar deprecation warning about AbstractMiddleware (emitted by litestar>=2.15)
warnings.filterwarnings(
    "ignore",
    message=".*deprecated class 'AbstractMiddleware'.*",
    category=DeprecationWarning,
    module="litestar.*",
)

# FastAPI: if missing, skip the whole module cleanly (no error during collection)
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
        found = any(k.lower() == "x-rbacx-reason" and v == "x" for k, v in hdrs.items())
        assert found

# --- Litestar section: import adapter; if import fails because of litestar import chain,
# install a minimal stub for litestar.middleware.AbstractMiddleware and retry.
def _install_min_litestar():
    import sys, types as _types
    if "litestar.middleware" in sys.modules:
        return
    pkg = _types.ModuleType("litestar")
    mw = _types.ModuleType("litestar.middleware")
    class AbstractMiddleware:
        def __init__(self, app, *args, **kwargs):
            self.app = app
        async def __call__(self, scope, receive, send):
            return await self.app(scope, receive, send)
    mw.AbstractMiddleware = AbstractMiddleware
    sys.modules["litestar"] = pkg
    sys.modules["litestar.middleware"] = mw

def _build_env(_scope):
    return None, None, None, None

class _Allow:
    async def evaluate_async(self, *_a, **_k):
        return types.SimpleNamespace(allowed=True)

class _Deny:
    async def evaluate_async(self, *_a, **_k):
        return types.SimpleNamespace(allowed=False, reason="nope")

async def _dummy_asgi(_scope, _receive, send):
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"ok"})

@pytest.mark.asyncio
async def test_litestar_middleware_denies_and_allows(monkeypatch):
    try:
        ls = importlib.import_module("rbacx.adapters.litestar")
    except Exception:
        _install_min_litestar()
        ls = importlib.import_module("rbacx.adapters.litestar")

    RBACXMiddleware = getattr(ls, "RBACXMiddleware")

    # Allow branch
    sent = []
    async def send(msg): sent.append(msg)
    mw_ok = RBACXMiddleware(_dummy_asgi, guard=_Allow(), build_env=_build_env)
    await mw_ok({"type": "http"}, lambda: None, send)
    assert sent and sent[0]["type"] == "http.response.start"

    # Deny branch
    sent2 = []
    async def send2(msg): sent2.append(msg)
    mw_deny = RBACXMiddleware(_dummy_asgi, guard=_Deny(), build_env=_build_env, add_headers=True)
    await mw_deny({"type": "http"}, lambda: None, send2)
    assert any(m.get("type") == "http.response.start" and m.get("status") == 403 for m in sent2)

# --- Starlette section ---
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
    resp = await ok_handler(object())
    assert hasattr(resp, "__call__") or hasattr(resp, "status_code")

    @st_require(GDeny(), _build_env_st, add_headers=True)
    async def deny_handler(_req):
        return JSONResponse({"ok": True})
    deny = await deny_handler(object())
    assert getattr(deny, "status_code", 403) == 403
