# Modernized FastAPI adapter test.
# We do not depend on the legacy 'rbacx.adapters.fastapi_guard' shim anymore.
# The test only skips if FastAPI is not installed.
import asyncio
import inspect
import types

import pytest

fastapi = pytest.importorskip(
    "fastapi", exc_type=ImportError, reason="Optional dep: FastAPI not installed"
)
from rbacx.adapters import fastapi as fa


def _env(_req):
    from rbacx.core.model import Action, Context, Resource, Subject

    return Subject(id="u1"), Action("read"), Resource(type="doc"), Context(attrs={})


class _GuardDenyWithExplain:
    def is_allowed_sync(self, *_a, **_k) -> bool:
        return False

    def explain(self, *_a, **_k):
        return types.SimpleNamespace(reason="blocked", rule_id="RID", policy_id="PID")


@pytest.mark.filterwarnings("ignore::DeprecationWarning")
def test_fastapi_guard_noop_dependency():
    dep = fa.require_access(_GuardDenyWithExplain(), _env, add_headers=True)

    async def _runner():
        with pytest.raises(fastapi.HTTPException) as ei:
            maybe = dep(object())
            if inspect.iscoroutine(maybe):
                await maybe
        e = ei.value
        assert e.status_code == 403
        # Headers should be present because add_headers=True
        assert e.headers.get("X-RBACX-Reason") == "blocked"
        assert e.headers.get("X-RBACX-Rule") == "RID"
        assert e.headers.get("X-RBACX-Policy") == "PID"

    asyncio.run(_runner())
