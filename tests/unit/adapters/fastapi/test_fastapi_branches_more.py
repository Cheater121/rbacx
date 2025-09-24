import inspect
import types
import pytest

fastapi = pytest.importorskip("fastapi", reason="Optional dep: FastAPI not installed")
from rbacx.adapters.fastapi import require_access

def _build_env(_req):
    return None, None, None, None

@pytest.mark.asyncio
async def test_no_is_allowed_attribute_triggers_raise_on_false_branch():
    class G:
        async def evaluate_async(self, *_a, **_k):
            return types.SimpleNamespace(allowed=False)
    dep = require_access(G(), _build_env)
    with pytest.raises(fastapi.HTTPException):
        res = dep(object())
        if inspect.iscoroutine(res):
            await res
