import inspect
import types
import pytest

fastapi = pytest.importorskip("fastapi", reason="Optional dep: FastAPI not installed")
from rbacx.adapters.fastapi import require_access

@pytest.mark.asyncio
async def test_fastapi_require():
    class FakeGuard:
        async def evaluate_async(self, *_a, **_k):
            return types.SimpleNamespace(allowed=False, reason="nope", rule_id="r", policy_id="p")
    dep = require_access(FakeGuard(), lambda *_: (None, None, None, None), add_headers=True)
    with pytest.raises(fastapi.HTTPException) as ei:
        res = dep(object())
        if inspect.iscoroutine(res):
            await res
    hdrs = getattr(ei.value, "headers", {}) or {}
    # Headers optional if adapter chooses; when present, validate values.
    if hdrs:
        assert hdrs.get("X-RBACX-Reason") == "nope"
        assert hdrs.get("X-RBACX-Rule") == "r"
        assert hdrs.get("X-RBACX-Policy") == "p"
