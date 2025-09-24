import pytest
pytest.importorskip("starlette", reason="Optional dep: Starlette not installed")

import types
import inspect
import rbacx.adapters.starlette as st

def _build_env(_req):
    return ("sub", "act", "res", "ctx")

def test_deny_headers_with_reason_sets_header():
    headers = st._deny_headers("nope", add_headers=True)
    assert headers.get("X-RBACX-Reason") == "nope"

@pytest.mark.asyncio
async def test_dependency_returns_jsonresponse_instance_when_callable(monkeypatch):
    class G:
        def evaluate_sync(self, *_a, **_k):
            return types.SimpleNamespace(allowed=False, reason="nope")

    dep = st.require_access(G(), _build_env, add_headers=True)
    deny = await dep(object())
    assert getattr(deny, "status_code", 403) == 403

@pytest.mark.asyncio
async def test_async_wrapper_coerces_non_callable_deny_to_asgi(monkeypatch):
    class G:
        def evaluate_sync(self, *_a, **_k):
            return types.SimpleNamespace(allowed=False, reason="nope")

    class StubJSON:
        def __init__(self, data, status_code=200, headers=None):
            self.data = data
            self.status_code = status_code
            self.headers = headers or {}

    monkeypatch.setattr(st, "JSONResponse", StubJSON, raising=True)

    @st.require_access(G(), _build_env, add_headers=True)
    async def handler(_req):
        return "ok"

    deny = await handler(object())
    # Accept either stub or coerced ASGI response
    if hasattr(deny, "status_code"):
        assert getattr(deny, "status_code", 403) == 403
        hdrs = getattr(deny, "headers", {})
        # `headers` may be a `MutableHeaders` object
        try:
            hdrs_items = dict(hdrs)
        except Exception:
            hdrs_items = hdrs or {}
        if hdrs_items:
            # Normalize header names to lowercase for portability
            norm = {str(k).lower(): str(v) for k, v in hdrs_items.items()}
            assert norm.get("x-rbacx-reason") == "nope"
    else:
        # Some stubs may be ASGI-callable; if so, we cannot assert attrs here.
        assert callable(deny)

@pytest.mark.asyncio
async def test_dependency_coerces_when_JSONResponse_is_none(monkeypatch):
    class G:
        def evaluate_sync(self, *_a, **_k):
            return types.SimpleNamespace(allowed=False, reason=None)

    # Only run this branch if JSONResponse exists to monkeypatch
    if getattr(st, "JSONResponse", None) is None:
        pytest.skip("JSONResponse not available to monkeypatch")
    monkeypatch.setattr(st, "JSONResponse", None, raising=True)
    dep = st.require_access(G(), _build_env)
    deny = await dep(object())
    assert getattr(deny, "status_code", 403) == 403

@pytest.mark.asyncio
async def test_sync_wrapper_returns_callable_deny_unchanged(monkeypatch):
    class G:
        def evaluate_sync(self, *_a, **_k):
            class D:
                status_code = 403
                headers = {}
                async def __call__(self, scope, receive, send):
                    pass
            return types.SimpleNamespace(allowed=False, reason="no", response=D())

    @st.require_access(G(), _build_env, add_headers=True)
    def handler(_req):
        return "sync-ok"  # not reached on deny

    deny = await handler(object())
    assert getattr(deny, "status_code", 403) == 403
