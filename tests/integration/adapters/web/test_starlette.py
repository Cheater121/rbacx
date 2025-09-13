import inspect

import pytest

starlette = pytest.importorskip("starlette")

from dataclasses import dataclass

from starlette.applications import Starlette
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from rbacx.adapters.starlette import require_access as st_require

# --- Test doubles ------------------------------------------------------------


@dataclass
class Decision:
    allowed: bool
    reason: str | None = None


class FakeGuard:
    """Synchronous guard used for tests; mimics the production API shape."""

    def __init__(self, allowed: bool, reason: str | None = None):
        self._allowed = allowed
        self._reason = reason

    # boolean-only check
    def is_allowed_sync(self, sub, act, res, ctx) -> bool:
        return self._allowed

    # rich decision (preferred)
    def evaluate_sync(self, sub, act, res, ctx) -> Decision:
        return Decision(self._allowed, self._reason)

    # optional reason enrichment
    def explain_sync(self, sub, act, res, ctx) -> Decision:
        return Decision(self._allowed, self._reason)


def build_env(_request):
    """Build a minimal (Subject, Action, Resource, Context) tuple for the guard."""
    from rbacx.core.model import Action, Context, Resource, Subject

    return (Subject(id="u"), Action("read"), Resource(type="doc"), Context(attrs={}))


# --- API shape tests ---------------------------------------------------------


def test_st_require_returns_callable_endpoint():
    """Decorator must produce a callable endpoint (not a coroutine object)."""
    guard = FakeGuard(True)
    decorator = st_require(guard, build_env)

    assert callable(decorator), "require_access(guard, build_env) must return a decorator callable"

    # Async handler -> wrapped must be a callable function object (not a coroutine)
    async def async_ok(request):
        return JSONResponse({"ok": True})

    wrapped_async = decorator(async_ok)
    assert callable(wrapped_async)
    assert not inspect.iscoroutine(
        wrapped_async
    ), "Decorator must return a function, not a coroutine object"
    assert inspect.iscoroutinefunction(
        wrapped_async
    ), "Wrapped endpoint may be async function (that is correct)"

    # Sync handler -> wrapped must also be callable (Starlette will call it)
    def sync_ok(request):
        return PlainTextResponse("ok")

    wrapped_sync = decorator(sync_ok)
    assert callable(wrapped_sync)
    assert not inspect.iscoroutine(wrapped_sync)


# --- Integration tests with Starlette router --------------------------------


@pytest.mark.parametrize("handler_kind", ["sync", "async"])
def test_st_require_allows_and_denies(handler_kind):
    """Mount wrapped handlers on Starlette routes and verify 200/403 behavior."""
    guard_allow = FakeGuard(True)
    guard_deny = FakeGuard(False, "nope")

    def make_handler(kind):
        if kind == "sync":

            def h(_req):
                return JSONResponse({"x": 1})
        else:

            async def h(_req):
                return JSONResponse({"x": 1})

        return h

    allow_handler = st_require(guard_allow, build_env)(make_handler(handler_kind))
    deny_handler = st_require(guard_deny, build_env, add_headers=True)(make_handler(handler_kind))

    app = Starlette(
        routes=[
            Route("/ok", allow_handler),
            Route("/deny", deny_handler),
        ]
    )

    # IMPORTANT: use TestClient as a context manager to ensure lifespan is run.
    # See: https://www.starlette.io/lifespan/#running-lifespan-in-tests
    with TestClient(app) as client:
        r_ok = client.get("/ok")
        assert r_ok.status_code == 200 and r_ok.json() == {"x": 1}

        r_deny = client.get("/deny")
        assert r_deny.status_code == 403, "Denied access must return 403"

        # Body should carry some detail/reason/message.
        body = {}
        try:
            body = r_deny.json()
        except Exception:
            pass
        assert any(k in body for k in ("detail", "reason", "message"))

        # Headers are HTTPX Headers (dictionary-like, case-insensitive), not dict.
        # See: https://www.python-httpx.org/quickstart/#response-headers
        assert "x-rbacx-reason" in r_deny.headers
        assert r_deny.headers.get("x-rbacx-reason") == "nope"
