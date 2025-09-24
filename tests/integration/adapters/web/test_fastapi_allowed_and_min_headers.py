import inspect
import types
import pytest

fastapi = pytest.importorskip("fastapi", reason="Optional dep: FastAPI not installed")
from rbacx.adapters.fastapi import require_access

@pytest.mark.asyncio
async def test_fastapi_deny_without_headers():
    class _G:
        async def evaluate_async(self, *_a, **_k):
            return types.SimpleNamespace(allowed=False, reason=None)
    dep = require_access(_G(), lambda *_: (None, None, None, None))
    with pytest.raises(fastapi.HTTPException):
        res = dep(object())
        if inspect.iscoroutine(res):
            await res
