import types

import pytest


@pytest.mark.asyncio
async def test_coerce_asgi_json_response_fallback_jsonresponse(monkeypatch):
    """
    Covers lines 30-33: when _ASGIJSONResponse is None, but JSONResponse is available,
    the function must return JSONResponse(data, status_code, headers).
    """
    pytest.importorskip("starlette")
    import rbacx.adapters.starlette as st_mod

    captured = {}

    class StubJSONResponse:
        def __init__(self, data, status_code=200, headers=None):
            captured["data"] = data
            captured["status_code"] = status_code
            captured["headers"] = headers

    # Force the fallback branch (no native ASGI JSON response)
    monkeypatch.setattr(st_mod, "_ASGIJSONResponse", None, raising=False)
    monkeypatch.setattr(st_mod, "JSONResponse", StubJSONResponse, raising=False)

    result = st_mod._coerce_asgi_json_response({"hello": "world"}, 418, {"X-K": "V"})
    assert isinstance(result, StubJSONResponse)
    assert captured["data"] == {"hello": "world"}
    assert captured["status_code"] == 418
    assert captured["headers"] == {"X-K": "V"}


def test_eval_guard_sync_path_indirect():
    """
    Covers lines 42-43 indirectly via require_access: when guard exposes is_allowed_sync,
    the decorator should take the fast path (allowed).
    """
    pytest.importorskip("starlette")
    from starlette.requests import Request

    import rbacx.adapters.starlette as st_mod

    class Guard:
        def is_allowed_sync(self, sub, act, res, ctx):
            assert (sub, act, res, ctx) == ("u", "a", "r", {"c": 1})
            return True  # fast-path

    def build_env(_req):
        return ("u", "a", "r", {"c": 1})

    dependency = st_mod.require_access(Guard(), build_env, add_headers=True)

    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "GET",
        "path": "/",
        "raw_path": b"/",
        "headers": [],
        "query_string": b"",
        "scheme": "http",
        "client": ("127.0.0.1", 12345),
        "server": ("test", 80),
    }
    req = Request(scope)

    # Allowed -> dependency returns None (no deny)
    import anyio

    deny = anyio.run(lambda: dependency(req))
    assert deny is None


@pytest.mark.asyncio
async def test_dependency_returns_none_when_allowed_true():
    """
    Covers lines 68-69: dependency should return None (no deny) when allowed=True.
    """
    pytest.importorskip("starlette")
    from starlette.requests import Request

    import rbacx.adapters.starlette as st_mod

    class Guard:
        def is_allowed_sync(self, *_args, **_kwargs):
            return True  # ensure allowed path

    def build_env(_req):
        return ("u", "a", "r", {"c": 1})

    dependency = st_mod.require_access(Guard(), build_env, add_headers=True)

    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "GET",
        "path": "/",
        "raw_path": b"/",
        "headers": [],
        "query_string": b"",
        "scheme": "http",
        "client": ("127.0.0.1", 12345),
        "server": ("test", 80),
    }
    req = Request(scope)

    deny = await dependency(req)
    assert deny is None


@pytest.mark.asyncio
async def test_async_endpoint_allows_and_calls_handler():
    """
    Covers the tail of 82-94: deny is None on async handler -> returns await handler(request).
    """
    pytest.importorskip("starlette")
    from starlette.requests import Request

    import rbacx.adapters.starlette as st_mod

    class Guard:
        def is_allowed_sync(self, *_args, **_kwargs):
            return True

    def build_env(_req):
        return ("u", "a", "r", {"c": 1})

    decorator = st_mod.require_access(Guard(), build_env, add_headers=True)

    async def handler(request):
        return {"ok": True, "path": request.url.path}

    wrapped = decorator(handler)

    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "GET",
        "path": "/hello",
        "raw_path": b"/hello",
        "headers": [],
        "query_string": b"",
        "scheme": "http",
        "client": ("127.0.0.1", 12345),
        "server": ("test", 80),
    }
    req = Request(scope)

    result = await wrapped(req)
    assert result == {"ok": True, "path": "/hello"}


@pytest.mark.asyncio
async def test_sync_endpoint_returns_callable_deny_when_dependency_returns_response(monkeypatch):
    """
    Covers line 106: when dependency returns an ASGI-callable deny (e.g. a Response),
    the wrapper must 'return deny' directly (no coercion, no threadpool).
    """
    pytest.importorskip("starlette")
    from starlette.requests import Request
    from starlette.responses import JSONResponse  # Response objects are ASGI-callable.

    import rbacx.adapters.starlette as st_mod

    class Guard:
        def is_allowed_sync(self, *_args, **_kwargs):
            return False  # force deny-branch

    def build_env(_req):
        return ("u", "a", "r", {"c": 1})

    decorator = st_mod.require_access(Guard(), build_env, add_headers=True)

    # sync handler (so we go through sync wrapper)
    def handler(_request):
        return {"should_not": "be_called"}

    wrapped = decorator(handler)

    # ASGI-callable deny
    deny_callable = JSONResponse({"detail": "Forbidden"}, status_code=403)

    # Patch the closure `_dependency` to return our callable deny
    freevars = wrapped.__code__.co_freevars
    assert "_dependency" in freevars
    dep_idx = freevars.index("_dependency")
    cells = list(wrapped.__closure__)

    async def fake_dependency(_request):
        return deny_callable

    def make_cell(value):
        return (lambda x: lambda: x)(value).__closure__[0]

    cells[dep_idx] = make_cell(fake_dependency)
    wrapped_patched = types.FunctionType(
        wrapped.__code__, wrapped.__globals__, wrapped.__name__, wrapped.__defaults__, tuple(cells)
    )

    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "POST",
        "path": "/tp",
        "raw_path": b"/tp",
        "headers": [],
        "query_string": b"",
        "scheme": "http",
        "client": ("127.0.0.1", 12345),
        "server": ("test", 80),
    }
    req = Request(scope)

    result = await wrapped_patched(req)
    assert result is deny_callable  # covered 106


@pytest.mark.asyncio
async def test_sync_endpoint_calls_real_run_in_threadpool():
    """
    Covers line 107: deny is None on sync handler -> must execute
    `return await run_in_threadpool(handler, request)` (real threadpool call).
    """
    pytest.importorskip("starlette")
    from starlette.requests import Request

    import rbacx.adapters.starlette as st_mod

    class Guard:
        def is_allowed_sync(self, *_args, **_kwargs):
            return True  # ensure allow path (deny is None)

    def build_env(_req):
        return ("u", "a", "r", {"c": 1})

    decorator = st_mod.require_access(Guard(), build_env, add_headers=True)

    # Sync handler to enforce the sync-wrapper path (uses Starlette's real threadpool)
    def handler(request):
        # Use a bit of data from the request so mypy/linters don't complain
        return {"ok": "real-threadpool", "method": request.method}

    wrapped = decorator(handler)

    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "PUT",
        "path": "/real",
        "raw_path": b"/real",
        "headers": [],
        "query_string": b"",
        "scheme": "http",
        "client": ("127.0.0.1", 12345),
        "server": ("test", 80),
    }
    req = Request(scope)

    # No monkeypatch: we await the actual run_in_threadpool implementation
    result = await wrapped(req)
    assert result == {"ok": "real-threadpool", "method": "PUT"}
