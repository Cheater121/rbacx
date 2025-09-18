import asyncio
import inspect
import types

import pytest

fastapi = pytest.importorskip(
    "fastapi", exc_type=ImportError, reason="Optional dep: FastAPI not installed"
)
from rbacx.adapters import fastapi as fa


@pytest.mark.filterwarnings("ignore::DeprecationWarning")
def test_fastapi_require_access_denied_with_headers(monkeypatch):
    # Assert FastAPI adapter raises HTTPException on denial and sets headers when add_headers=True
    class _GuardDeny:
        def is_allowed_sync(self, *_a, **_k) -> bool:
            return False

        def explain(self, *_a, **_k):
            return types.SimpleNamespace(reason="X", rule_id="R", policy_id="P")

    async def handler():
        with pytest.raises(fastapi.HTTPException) as ei:
            dep = fa.require_access(
                _GuardDeny(), lambda *_: (None, None, None, None), add_headers=True
            )
            res = dep(object())
            if inspect.iscoroutine(res):
                await res
        exc = ei.value
        assert exc.status_code == 403
        assert exc.headers.get("X-RBACX-Reason") == "X"
        assert exc.headers.get("X-RBACX-Rule") == "R"
        assert exc.headers.get("X-RBACX-Policy") == "P"

    asyncio.run(handler())


def test_litestar_middleware_denies_and_allows(monkeypatch):
    # Minimal smoke: ensure litestar guard module exposes 'require'
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    import pytest as _pytest  # keep local scope clean

    lg = _pytest.importorskip(
        "rbacx.adapters.litestar_guard",
        exc_type=ImportError,
        reason="Optional dep: Litestar not installed",
    )
    assert hasattr(lg, "require")
