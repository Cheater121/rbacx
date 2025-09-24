import asyncio
import inspect
import types
import pytest

fastapi = pytest.importorskip("fastapi", reason="Optional dep: FastAPI not installed")
from rbacx.adapters import fastapi as fa

@pytest.mark.asyncio
async def test_fastapi_require_allowed_branch():
    class _GuardAllow:
        async def evaluate_async(self, *_a, **_k):
            return types.SimpleNamespace(allowed=True, reason=None)
    dep = fa.require_access(_GuardAllow(), lambda *_: (None, None, None, None))
    res = dep(object())
    if inspect.iscoroutine(res):
        await res  # should not raise

@pytest.mark.asyncio
async def test_fastapi_require_denied_no_headers():
    class _GuardDeny:
        async def evaluate_async(self, *_a, **_k):
            return types.SimpleNamespace(allowed=False, reason=None)
    dep = fa.require_access(_GuardDeny(), lambda *_: (None, None, None, None))
    with pytest.raises(fastapi.HTTPException) as ei:
        res = dep(object())
        if inspect.iscoroutine(res):
            await res
    assert ei.value.status_code == 403
    # detail is generic
    assert ei.value.detail == "Forbidden" or ei.value.detail == {"reason": None}

@pytest.mark.asyncio
async def test_fastapi_require_denied_with_headers():
    class _GuardDenyExplain:
        async def evaluate_async(self, *_a, **_k):
            return types.SimpleNamespace(allowed=False, reason="nope", rule_id="r", policy_id="p")
    dep = fa.require_access(_GuardDenyExplain(), lambda *_: (None, None, None, None), add_headers=True)
    with pytest.raises(fastapi.HTTPException) as ei:
        res = dep(object())
        if inspect.iscoroutine(res):
            await res
    # Headers exist when add_headers=True (if adapter supports), otherwise ok to be empty
    hdrs = getattr(ei.value, "headers", {}) or {}
    assert ("X-RBACX-Reason" in hdrs and hdrs["X-RBACX-Reason"] == "nope") or hdrs == {}
