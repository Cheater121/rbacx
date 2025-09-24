import inspect
import types
import pytest

fastapi = pytest.importorskip("fastapi", reason="Optional dep: FastAPI not installed")
from rbacx.adapters.fastapi import require_access

def _build_env(_req):
    return None, None, None, None

@pytest.mark.asyncio
async def test_fastapi_dependency_builds_reason_headers():
    class G:
        async def evaluate_async(self, *_a, **_k):
            return types.SimpleNamespace(allowed=False, reason="nope", rule_id="r", policy_id="p")
    dep = require_access(G(), _build_env, add_headers=True)
    with pytest.raises(fastapi.HTTPException) as ei:
        res = dep(object())
        if inspect.iscoroutine(res):
            await res
    hdrs = getattr(ei.value, "headers", {}) or {}
    if hdrs:
        assert hdrs["X-RBACX-Reason"] == "nope"
        assert hdrs["X-RBACX-Rule"] == "r"
        assert hdrs["X-RBACX-Policy"] == "p"
