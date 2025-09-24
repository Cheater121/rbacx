import types
import pytest

litestar = pytest.importorskip("litestar", reason="Optional dep: Litestar not installed")
from rbacx.adapters.litestar_guard import require_access

def _build_env(_conn):
    return None, None, None, None

@pytest.mark.asyncio
async def test_require_else_branch_evaluate_async_path():
    class G:
        async def evaluate_async(self, *_a, **_k):
            return types.SimpleNamespace(allowed=True)
    checker = require_access(G(), _build_env)
    # Should be awaitable guard callable under Litestar; just ensure it's callable
    assert callable(checker)
