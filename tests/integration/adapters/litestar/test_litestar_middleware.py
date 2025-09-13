# tests/integration/adapters/litestar/test_litestar_middleware.py
import importlib
import sys
import types

import pytest


def _purge_litestar_modules() -> None:
    """Remove all already loaded 'litestar' modules to avoid pulling a broken installation."""
    for name in list(sys.modules):
        if name == "litestar" or name.startswith("litestar."):
            sys.modules.pop(name, None)


def _install_litestar_stubs(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Provide minimal 'litestar' stubs sufficient for importing rbacx.adapters.litestar,
    without touching Starlette/FastAPI, etc.
    """
    pkg = types.ModuleType("litestar")
    pkg.__path__ = []  # make it a package
    monkeypatch.setitem(sys.modules, "litestar", pkg)

    mw_mod = types.ModuleType("litestar.middleware")

    class AbstractMiddleware:  # minimal API expected by RBACXMiddleware
        def __init__(self, app, **kwargs):
            self.app = app

    mw_mod.AbstractMiddleware = AbstractMiddleware
    monkeypatch.setitem(sys.modules, "litestar.middleware", mw_mod)

    types_mod = types.ModuleType("litestar.types")
    types_mod.Receive = object
    types_mod.Scope = dict
    types_mod.Send = object
    monkeypatch.setitem(sys.modules, "litestar.types", types_mod)


def _build_env(scope):
    # Import models only inside the helper—just like in the real code
    from rbacx.core.model import Action, Context, Resource, Subject

    return Subject(id="s1"), Action("read"), Resource(type="doc"), Context(attrs={})


@pytest.mark.asyncio
async def test_middleware_allows_and_calls_app(
    monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest
):
    _purge_litestar_modules()
    _install_litestar_stubs(monkeypatch)

    # Force reimport RBACX module so it binds to the litestar stub
    sys.modules.pop("rbacx.adapters.litestar", None)
    lit_mod = importlib.import_module("rbacx.adapters.litestar")

    # Clean it up after the test so other tests don't see our version
    request.addfinalizer(lambda: sys.modules.pop("rbacx.adapters.litestar", None))

    called = []

    async def app(scope, receive, send):
        called.append(True)
        # valid ASGI messages for a 200 response
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    class Guard:
        async def evaluate_async(self, subject, action, resource, context):
            return types.SimpleNamespace(allowed=True, reason=None)

    mw = lit_mod.RBACXMiddleware(app=app, guard=Guard(), build_env=_build_env)
    scope = {"type": "http", "path": "/"}

    async def recv():
        return {}

    sent = []

    async def send(msg):
        sent.append(msg)

    await mw(scope, recv, send)
    assert called == [True]
    start = next((m for m in sent if m.get("type") == "http.response.start"), None)
    assert start and start.get("status") == 200


@pytest.mark.asyncio
async def test_middleware_denies_and_returns_403(
    monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest
):
    _purge_litestar_modules()
    _install_litestar_stubs(monkeypatch)

    sys.modules.pop("rbacx.adapters.litestar", None)
    lit_mod = importlib.import_module("rbacx.adapters.litestar")
    request.addfinalizer(lambda: sys.modules.pop("rbacx.adapters.litestar", None))

    called = []

    async def app(scope, receive, send):
        called.append(True)

    class Guard:
        async def evaluate_async(self, subject, action, resource, context):
            return types.SimpleNamespace(allowed=False, reason="nope")

    mw = lit_mod.RBACXMiddleware(app=app, guard=Guard(), build_env=_build_env)
    scope = {"type": "http", "path": "/"}

    async def recv():
        return {}

    sent = []

    async def send(msg):
        sent.append(msg)

    await mw(scope, recv, send)
    # The app must not be called
    assert called == []
    # Should see response start with 403
    start = next((m for m in sent if m.get("type") == "http.response.start"), None)
    assert start and start.get("status") == 403


@pytest.mark.asyncio
async def test_middleware_non_http_passthrough(
    monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest
):
    _purge_litestar_modules()
    _install_litestar_stubs(monkeypatch)

    sys.modules.pop("rbacx.adapters.litestar", None)
    lit_mod = importlib.import_module("rbacx.adapters.litestar")
    request.addfinalizer(lambda: sys.modules.pop("rbacx.adapters.litestar", None))

    called = []

    async def app(scope, receive, send):
        called.append(True)

    class Guard:
        async def evaluate_async(self, *a, **k):
            raise AssertionError("guard must not be called for non-HTTP scope")

    mw = lit_mod.RBACXMiddleware(app=app, guard=Guard(), build_env=_build_env)
    scope = {"type": "websocket"}  # non-HTTP

    async def recv():
        return {}

    async def send(msg):
        pass

    await mw(scope, recv, send)
    assert called == [True]
