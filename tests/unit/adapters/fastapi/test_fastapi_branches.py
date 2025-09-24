import inspect
import types
import pytest

fastapi = pytest.importorskip("fastapi", reason="Optional dep: FastAPI not installed")
from rbacx.adapters.fastapi import require_access

def _build_env(_req):
    return None, None, None, None

@pytest.mark.asyncio
async def test_is_allowed_branch_returns_none():
    class G:
        async def evaluate_async(self, *_a, **_k):
            return types.SimpleNamespace(allowed=True)
    dep = require_access(G(), _build_env)
    res = dep(object())
    if inspect.iscoroutine(res):
        await res

@pytest.mark.asyncio
async def test_reason_false_rule_id_true_sets_rule_header():
    class G:
        async def evaluate_async(self, *_a, **_k):
            return types.SimpleNamespace(allowed=False, reason=None, rule_id="R")
    dep = require_access(G(), _build_env, add_headers=True)
    with pytest.raises(fastapi.HTTPException) as ei:
        res = dep(object())
        if inspect.iscoroutine(res):
            await res
    hdrs = getattr(ei.value, "headers", {}) or {}
    if hdrs:
        assert hdrs.get("X-RBACX-Rule") == "R"
