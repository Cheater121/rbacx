import inspect
import types
import pytest

fastapi = pytest.importorskip("fastapi", reason="Optional dep: FastAPI not installed")
from rbacx.adapters.fastapi import require_access

@pytest.mark.asyncio
async def test_fastapi_guard_noop_dependency():
    class _G:
        async def evaluate_async(self, *_a, **_k):
            return types.SimpleNamespace(allowed=True)
    dep = require_access(_G(), lambda *_: (None, None, None, None))
    res = dep(object())
    if inspect.iscoroutine(res):
        await res  # should not raise
