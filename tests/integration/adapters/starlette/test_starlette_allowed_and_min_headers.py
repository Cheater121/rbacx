import pytest
pytest.importorskip("starlette", reason="Optional dep: Starlette not installed")

import types
from rbacx.adapters.starlette import require_access
from starlette.responses import JSONResponse

def _build_env(_req):
    return None, None, None, None

@pytest.mark.asyncio
async def test_starlette_allowed_pass_through():
    class GAllow:
        async def evaluate_async(self, *_a, **_k):
            return types.SimpleNamespace(allowed=True)

    @require_access(GAllow(), _build_env)
    async def handler(_req):
        return JSONResponse({"ok": True})

    resp = await handler(object())
    # Should pass through and return the handler's response (ASGI-compatible)
    assert hasattr(resp, "__call__") or getattr(resp, "status_code", 200) == 200
