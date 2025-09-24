from __future__ import annotations

from typing import Any, Callable, Optional, ParamSpec, TypeVar

# Optional Starlette JSONResponse
try:
    from starlette.responses import JSONResponse as _ASGIJSONResponse  # type: ignore[import-not-found]
except Exception:  # pragma: no cover
    _ASGIJSONResponse = None  # type: ignore

P = ParamSpec("P")
T = TypeVar("T")

try:
    from starlette.concurrency import run_in_threadpool as run_in_threadpool  # type: ignore[import-not-found]
except Exception:  # pragma: no cover
    async def run_in_threadpool(func: Callable[P, T], *args: P.args, **kwargs: P.kwargs) -> T:
        return func(*args, **kwargs)

# Module-level JSONResponse that tests may monkeypatch
JSONResponse = _ASGIJSONResponse  # may be replaced in tests

from ._common import EnvBuilder

def _coerce_asgi_json_response(
    data: Any,
    status_code: int,
    headers: Optional[dict[str, str]] = None,
):
    if _ASGIJSONResponse is None:  # Starlette missing; use whatever JSONResponse is patched to
        if JSONResponse is None:
            raise RuntimeError("JSONResponse is not available")  # pragma: no cover
        return JSONResponse(data, status_code=status_code, headers=headers)
    return _ASGIJSONResponse(data, status_code=status_code, headers=headers)

def _eval_guard(guard: Any, env: tuple[Any, Any, Any, Any]) -> tuple[bool, Optional[str], Optional[str], Optional[str]]:
    sub, act, res, ctx = env
    # Prefer evaluate_sync (richer), then is_allowed_sync, then is_allowed
    if hasattr(guard, "evaluate_sync"):
        d = guard.evaluate_sync(sub, act, res, ctx)
        return bool(getattr(d, "allowed", False)), getattr(d, "reason", None), getattr(d, "rule_id", None), getattr(d, "policy_id", None)
    if hasattr(guard, "is_allowed_sync"):
        return bool(guard.is_allowed_sync(sub, act, res, ctx)), None, None, None
    return bool(getattr(guard, "is_allowed", lambda *_: False)(sub, act, res, ctx)), None, None, None

def _deny_headers(reason: Optional[str], add_headers: bool) -> dict[str, str]:
    if not add_headers:
        return {}
    headers: dict[str, str] = {}
    if reason:
        headers["X-RBACX-Reason"] = str(reason)
    return headers

def require_access(
    guard: Any,
    build_env: EnvBuilder,
    add_headers: bool = False,
) -> Callable[..., Any]:
    """
    Starlette adapter that works both:
      - as a decorator on an endpoint (returns an async endpoint)
      - as a dependency-like callable: `dep = require_access(...); await dep(request)`
    """

    async def _dependency(request: Any):
        env = build_env(request)
        allowed, reason, rule_id, policy_id = _eval_guard(guard, env)
        if allowed:
            return None
        payload = {"detail": reason or "Forbidden"}
        hdrs = _deny_headers(reason, add_headers)
        if JSONResponse is None:
            return _coerce_asgi_json_response(payload, 403, headers=hdrs)
        return JSONResponse(payload, status_code=403, headers=hdrs)

    def _decorator_or_dependency(arg: Any):
        # If arg looks like a Starlette handler (callable), act as decorator.
        if callable(arg):
            handler = arg
            is_async = bool(getattr(handler, "__code__", None) and handler.__code__.co_flags & 0x80)

            if is_async:
                async def _endpoint_async(request: Any):
                    deny = await _dependency(request)
                    if deny is not None:
                        # If deny is not ASGI-callable, coerce
                        if not callable(deny):
                            return _coerce_asgi_json_response(
                                getattr(deny, "data", {"detail": "Forbidden"}),
                                getattr(deny, "status_code", 403),
                                getattr(deny, "headers", None),
                            )
                        return deny
                    return await handler(request)
                return _endpoint_async

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

        # Otherwise, act as dependency: expect `request` and return a denial response or None.
        return _dependency(arg)

    return _decorator_or_dependency
