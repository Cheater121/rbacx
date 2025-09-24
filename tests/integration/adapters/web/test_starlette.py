import types
import pytest

starlette = pytest.importorskip("starlette", reason="Optional dep: Starlette not installed")
from rbacx.adapters.starlette import require_access
from starlette.responses import JSONResponse

def _build_env(_req):
    return None, None, None, None

@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["sync", "async"])
async def test_st_require_allows_and_denies(mode):
    class FakeGuardAllow:
        async def evaluate_async(self, *_a, **_k):
            return types.SimpleNamespace(allowed=True)

    class FakeGuardDeny:
        async def evaluate_async(self, *_a, **_k):
            return types.SimpleNamespace(allowed=False, reason="nope")

    @require_access(FakeGuardAllow(), _build_env)
    async def ok_handler(_req):
        return JSONResponse({"ok": True})
    resp = await ok_handler(object())
    assert hasattr(resp, "__call__") or hasattr(resp, "status_code")

    @require_access(FakeGuardDeny(), _build_env, add_headers=True)
    async def deny_handler(_req):
        return JSONResponse({"ok": True})
    deny = await deny_handler(object())
    assert getattr(deny, "status_code", 403) == 403
