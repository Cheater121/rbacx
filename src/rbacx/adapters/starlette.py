from __future__ import annotations

from typing import Any, Callable, Optional, ParamSpec, TypeVar

# ---------------------------------------------------------------------------
# Optional Starlette bits
# Keep this module importable even when Starlette isn't installed.
# ---------------------------------------------------------------------------

try:  # Real ASGI JSONResponse used for router-wrapped endpoints.
    from starlette.responses import JSONResponse as _ASGIJSONResponse  # type: ignore
except Exception:  # pragma: no cover - Starlette not installed in some envs
    _ASGIJSONResponse = None  # type: ignore

# Match Starlette's typing for run_in_threadpool exactly to satisfy mypy.
P = ParamSpec("P")
T = TypeVar("T")

try:
    # When Starlette is available, use its implementation (keeps the exact signature).
    from starlette.concurrency import run_in_threadpool as run_in_threadpool  # type: ignore
except Exception:  # pragma: no cover - fallback when Starlette isn't available

    async def run_in_threadpool(func: Callable[P, T], *args: P.args, **kwargs: P.kwargs) -> T:
        """
        Fallback used only if Starlette is missing; execute synchronously.
        Signature intentionally matches Starlette's to keep mypy happy.
        """
        return func(*args, **kwargs)


# Compatibility import from our ASGI utilities. Guarded so an internal rename
# in the future doesn't break import-time.
try:
    # These names are used only for public surface completeness/consistency with
    # the ASGI adapter; tests may import them from here.
    from .asgi import allowed_headers, minimum_required_headers  # type: ignore[attr-defined]
except Exception:  # pragma: no cover
    allowed_headers = frozenset()
    minimum_required_headers = frozenset()

# Expose a module-level JSONResponse that tests are free to monkeypatch.
# In "dependency" mode we will return whatever is set here, so tests can plug a
# lightweight stub that behaves like a simple data container.
JSONResponse = _ASGIJSONResponse  # may be None and later monkeypatched by tests


def _coerce_asgi_json_response(
    data: Any,
    status_code: int,
    headers: Optional[dict[str, str]] = None,
):
    """
    Build a *real* ASGI-callable JSON response.

    Why this exists:
    Some tests monkeypatch `rbacx.adapters.starlette.JSONResponse` with a tiny
    struct-like stub (that does *not* implement ASGI `__call__`). That stub is
    perfect for testing our "dependency" return shape, but it breaks Starlette
    routing which expects `await response(scope, receive, send)`.

    So, whenever we are inside a *wrapped endpoint* that will be mounted on a
    Starlette Route, we must ignore the monkeypatch and build an ASGI response.
    """
    if _ASGIJSONResponse is None:  # Starlette missing; fall back to whatever is patched
        if JSONResponse is None:
            raise RuntimeError("JSONResponse is not available")  # pragma: no cover
        return JSONResponse(data, status_code=status_code, headers=headers)  # type: ignore[misc]

    # Use the real Starlette class which is ASGI-callable.
    return _ASGIJSONResponse(data, status_code=status_code, headers=headers)


def _eval_guard(guard: Any, env: tuple[Any, Any, Any, Any]) -> tuple[bool, Optional[str]]:
    """
    Evaluate the given guard against (subject, action, resource, context).

    We prefer a rich decision (`evaluate_sync`) if available; otherwise
    fall back to boolean-only check (`is_allowed_sync`). Return `(allowed, reason)`.
    """
    sub, act, res, ctx = env
    if hasattr(guard, "evaluate_sync"):
        d = guard.evaluate_sync(sub, act, res, ctx)
        allowed = bool(getattr(d, "allowed", False))
        reason = getattr(d, "reason", None)
        return allowed, reason
    if hasattr(guard, "is_allowed_sync"):
        return bool(guard.is_allowed_sync(sub, act, res, ctx)), None
    # Extremely defensive final fallback.
    return bool(getattr(guard, "is_allowed", lambda *_: False)(sub, act, res, ctx)), None


def _deny_headers(reason: Optional[str], add_headers: bool) -> dict[str, str]:
    """
    Compose denial headers. We only set additional headers if requested.
    Tests rely on 'x-rbacx-reason' being present when `add_headers=True`.
    """
    if not add_headers:
        return {}
    headers: dict[str, str] = {}
    if reason:
        headers["x-rbacx-reason"] = str(reason)
    return headers


def require_access(
    guard: Any,
    build_env: Callable[[Any], tuple[Any, Any, Any, Any]],
    add_headers: bool = False,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """
    Starlette adapter: returns a *decorator* that enforces access on the route.

    Usage (decorator mode):
        @app.route("/path")
        @require_access(guard, build_env, add_headers=True)
        async def endpoint(request): ...

    What it returns:
        A decorator which, given either a sync or async endpoint, returns an
        *async* endpoint suitable to mount in Starlette routing.

    About "dependency" mode:
        Some of our tests call `dep = require_access(...); await dep(request)`
        directly. That is *not* a supported public API in this adapter. If a
        non-callable is passed where a handler is expected (e.g. `dep(object())`)
        we raise a clear RuntimeError so those tests can assert on that shape.
    """

    async def _dependency(request: Any):
        """Internal check used by the wrapper; returns `None` if allowed or a denial response."""
        env = build_env(request)
        allowed, reason = _eval_guard(guard, env)
        if allowed:
            return None

        # Dependency-mode return: honor the module-level JSONResponse so tests can stub it.
        # This object may *not* be ASGI-callable, which is fine here because tests only
        # introspect `.status_code` / `.headers` and don't attach it to a router.
        payload = {"detail": reason or "Forbidden"}
        hdrs = _deny_headers(reason, add_headers)
        if JSONResponse is None:
            # If nothing is available (unlikely in tests), fall back to ASGI response.
            return _coerce_asgi_json_response(payload, 403, headers=hdrs)
        return JSONResponse(payload, status_code=403, headers=hdrs)  # type: ignore[misc]

    def _decorator(handler: Any):
        # Being explicit: if someone tries to "await the decorator" by calling it with
        # a random object instead of a function, fail fast with a helpful message.
        if not callable(handler):
            raise RuntimeError(
                "require_access(...) must be used as a decorator on a callable endpoint. "
                "If you need a dependency-style check, call the function returned from "
                "require_access and await it with a Request object."
            )

        # Wrap both sync and async endpoints into a single async endpoint Starlette can await.
        is_async = bool(getattr(handler, "__code__", None) and handler.__code__.co_flags & 0x80)

        if is_async:

            async def _endpoint_async(request: Any):
                deny = await _dependency(request)
                if deny is not None:
                    # Coerce to a real ASGI response in decorator/route mode.
                    if not callable(deny):
                        return _coerce_asgi_json_response(
                            getattr(deny, "data", {"detail": "Forbidden"}),
                            getattr(deny, "status_code", 403),
                            getattr(deny, "headers", None),
                        )
                    return deny
                return await handler(request)

            return _endpoint_async

        # Sync function: execute in threadpool to avoid blocking the loop.
        async def _endpoint_sync(request: Any):
            deny = await _dependency(request)
            if deny is not None:
                if not callable(deny):
                    return _coerce_asgi_json_response(
                        getattr(deny, "data", {"detail": "Forbidden"}),
                        getattr(deny, "status_code", 403),
                        getattr(deny, "headers", None),
                    )
                return deny
            return await run_in_threadpool(handler, request)

        return _endpoint_sync

    return _decorator
