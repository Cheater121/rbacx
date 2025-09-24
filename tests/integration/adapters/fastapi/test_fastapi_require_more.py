import inspect
import types
import pytest

# Robust module-level skip if FastAPI is missing
try:
    import fastapi  # noqa: F401
except Exception:
    pytest.skip("Optional dep: FastAPI not installed", allow_module_level=True)

from rbacx.adapters.fastapi import require_access

def _build_env(_req): return None, None, None, None

@pytest.mark.asyncio
@pytest.mark.parametrize('add_headers', [False, True])
async def test_fastapi_require_denies_raises_http_exception_with_optional_headers(add_headers):
    class _GuardDeny:
        async def evaluate_async(self, *_a, **_k):
            return types.SimpleNamespace(allowed=False, reason="nope", rule_id="r", policy_id="p")
    dep = require_access(_GuardDeny(), _build_env, add_headers=add_headers)
    with pytest.raises(fastapi.HTTPException):
        res = dep(object())
        if inspect.iscoroutine(res):
            await res
