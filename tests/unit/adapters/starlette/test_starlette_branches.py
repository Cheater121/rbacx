import pytest

import rbacx.adapters.starlette as st

# ---------- helpers ----------


class _Decision:
    def __init__(self, allowed: bool, reason: str | None = None):
        self.allowed = allowed
        self.reason = reason


def _build_env(_req):
    # (subject, action, resource, context) — любые маркеры
    return ("sub", "act", "res", "ctx")


# ---------- 70–72: _coerce_asgi_json_response fallback when Starlette JSONResponse is missing ----------
def test_coerce_uses_module_JSONResponse_when_asgi_missing(monkeypatch):
    # Simulate "Starlette not installed"
    monkeypatch.setattr(st, "_ASGIJSONResponse", None, raising=True)

    class StubJSON:
        def __init__(self, data, status_code=200, headers=None):
            self.data = data
            self.status_code = status_code
            self.headers = headers

    monkeypatch.setattr(st, "JSONResponse", StubJSON, raising=True)

    resp = st._coerce_asgi_json_response({"ok": True}, 403, headers={"X": "1"})
    assert isinstance(resp, StubJSON)
    assert resp.data == {"ok": True}
    assert resp.status_code == 403
    assert resp.headers == {"X": "1"}


# ---------- 91–94: _eval_guard uses is_allowed_sync() branch ----------
def test_eval_guard_uses_is_allowed_sync_branch():
    class G:
        def is_allowed_sync(self, sub, act, res, ctx):
            return True

    allowed, reason = st._eval_guard(G(), _build_env(None))
    assert allowed is True
    assert reason is None


# ---------- 103, 105->107: _deny_headers with add_headers off, and with reason on ----------
def test_deny_headers_add_headers_false_is_empty():
    assert st._deny_headers("why", add_headers=False) == {}


def test_deny_headers_with_reason_sets_header():
    out = st._deny_headers("nope", add_headers=True)
    assert out == {"X-RBACX-Reason": "nope"}


# ---------- 148: dependency path returns module-level JSONResponse (callable ASGI stub) ----------
@pytest.mark.asyncio
async def test_dependency_returns_jsonresponse_instance_when_callable(monkeypatch):
    # JSONResponse is an ASGI-callable stub; wrapper should return it directly
    class ASGIStub:
        def __init__(self, data, status_code=200, headers=None):
            self.data = data
            self.status_code = status_code
            self.headers = headers or {}

        async def __call__(self, scope, receive, send):
            return None

    monkeypatch.setattr(st, "JSONResponse", ASGIStub, raising=True)

    class G:
        def evaluate_sync(self, sub, act, res, ctx):
            return _Decision(False, "nope")

    @st.require_access(G(), _build_env, add_headers=True)
    async def handler(_req):
        return "OK"  # not reached

    deny = await handler(object())
    # The denial object is the ASGI JSONResponse returned from dependency branch
    assert isinstance(deny, ASGIStub)
    assert deny.status_code == 403
    assert deny.data == {"detail": "nope"}
    assert deny.headers.get("X-RBACX-Reason") == "nope"


# ---------- 176: async handler denied -> wrapper coerces NON-callable deny into ASGI response ----------
@pytest.mark.asyncio
async def test_async_wrapper_coerces_non_callable_deny_to_asgi(monkeypatch):
    # Simulate no Starlette JSONResponse available at import time
    monkeypatch.setattr(st, "_ASGIJSONResponse", None, raising=True)

    # Non-callable dependency-mode JSONResponse stub (no __call__)
    class PlainJSON:
        def __init__(self, data, status_code=200, headers=None):
            self.data = data
            self.status_code = status_code
            self.headers = headers

    monkeypatch.setattr(st, "JSONResponse", PlainJSON, raising=True)

    # Provide an ASGI-capable class for coercion (_coerce_asgi_json_response uses it when _ASGIJSONResponse is None)
    class ASGIResp:
        def __init__(self, data, status_code=200, headers=None):
            self.data = data
            self.status_code = status_code
            self.headers = headers or {}

        async def __call__(self, scope, receive, send):
            return None

    # Monkeypatch the private ASGI class used by coercion path
    monkeypatch.setattr(st, "_ASGIJSONResponse", ASGIResp, raising=True)

    class G:
        def evaluate_sync(self, sub, act, res, ctx):
            return _Decision(False, "nope")

    @st.require_access(G(), _build_env, add_headers=True)
    async def handler(_req):
        return "OK"  # not reached

    deny_asgi = await handler(object())
    # Wrapper should have coerced non-callable deny into an ASGI-capable response
    assert isinstance(deny_asgi, ASGIResp)
    assert deny_asgi.status_code == 403
    assert deny_asgi.data == {"detail": "nope"}
    assert deny_asgi.headers.get("X-RBACX-Reason") == "nope"


# ---------- 191: sync handler allowed -> executed via run_in_threadpool ----------
@pytest.mark.asyncio
async def test_sync_handler_allowed_runs_in_threadpool(monkeypatch):
    called = {}

    async def fake_run_in_threadpool(func, *args, **kwargs):
        called["hit"] = True
        return func(*args, **kwargs)

    monkeypatch.setattr(st, "run_in_threadpool", fake_run_in_threadpool, raising=True)

    class G:
        def is_allowed_sync(self, sub, act, res, ctx):
            return True

    @st.require_access(G(), _build_env, add_headers=False)
    def handler(_req):
        return "sync-ok"

    out = await handler(object())
    assert out == "sync-ok"
    assert called.get("hit") is True


# ---------- extra safety: decorator called with non-callable must raise (clear message) ----------
def test_decorator_raises_on_non_callable_handler():
    dep = st.require_access(object(), _build_env, add_headers=False)
    with pytest.raises(RuntimeError):
        dep(object())  # passing a non-callable as "handler"


# ---------- 94: _eval_guard final fallback uses guard.is_allowed ----------
def test_eval_guard_final_fallback_is_allowed():
    import rbacx.adapters.starlette as st

    class G:
        # No evaluate_sync / is_allowed_sync; only is_allowed -> triggers final fallback
        def is_allowed(self, sub, act, res, ctx):
            return True

    allowed, reason = st._eval_guard(G(), ("s", "a", "r", "c"))
    assert allowed is True
    assert reason is None


# ---------- 105->107: _deny_headers with add_headers=True but no reason ----------
def test_deny_headers_add_headers_true_without_reason():
    import rbacx.adapters.starlette as st

    assert st._deny_headers(None, add_headers=True) == {}


# ---------- 148: dependency branch — JSONResponse is None => _coerce_asgi_json_response used ----------
@pytest.mark.asyncio
async def test_dependency_coerces_when_JSONResponse_is_none(monkeypatch):
    import rbacx.adapters.starlette as st

    # Make JSONResponse unavailable so _dependency calls _coerce_asgi_json_response(...)
    monkeypatch.setattr(st, "JSONResponse", None, raising=True)

    # Provide an ASGI-callable response class for coercion
    class ASGIResp:
        def __init__(self, data, status_code=200, headers=None):
            self.data = data
            self.status_code = status_code
            self.headers = headers or {}

        async def __call__(self, scope, receive, send):
            return None

    monkeypatch.setattr(st, "_ASGIJSONResponse", ASGIResp, raising=True)

    class G:
        def evaluate_sync(self, sub, act, res, ctx):
            # force denial so dependency path returns a response
            class D:  # decision-like
                allowed = False
                reason = "blocked"

            return D()

    @st.require_access(G(), lambda req: ("s", "a", "r", "c"), add_headers=True)
    async def endpoint(_req):
        return "OK"  # not reached

    # The wrapper will return the ASGIResp produced INSIDE _dependency (coercion path)
    deny = await endpoint(object())
    assert isinstance(deny, ASGIResp)
    assert deny.status_code == 403
    assert deny.data == {"detail": "blocked"}
    assert deny.headers.get("X-RBACX-Reason") == "blocked"


# ---------- 191: sync wrapper — callable deny is returned as-is (no extra coercion) ----------
@pytest.mark.asyncio
async def test_sync_wrapper_returns_callable_deny_unchanged(monkeypatch):
    import rbacx.adapters.starlette as st

    # Module-level JSONResponse returns an ASGI-callable object
    class ASGIStub:
        def __init__(self, data, status_code=200, headers=None):
            self.data = data
            self.status_code = status_code
            self.headers = headers or {}

        async def __call__(self, scope, receive, send):
            return None

    monkeypatch.setattr(st, "JSONResponse", ASGIStub, raising=True)

    class G:
        def evaluate_sync(self, sub, act, res, ctx):
            class D:
                allowed = False
                reason = "nope"

            return D()

    @st.require_access(G(), lambda req: ("s", "a", "r", "c"), add_headers=True)
    def handler(_req):
        return "sync-ok"  # not reached on deny

    # For sync handler: wrapper should return the callable deny object directly (line 191)
    deny = await handler(object())
    assert isinstance(deny, ASGIStub)
    assert deny.status_code == 403
    assert deny.data == {"detail": "nope"}
    assert deny.headers.get("X-RBACX-Reason") == "nope"
