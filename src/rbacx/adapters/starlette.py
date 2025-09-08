
from __future__ import annotations

from typing import Any, Callable, Dict, Tuple

try:  # Optional dependency boundary
    from starlette.responses import JSONResponse  # type: ignore
except Exception:  # pragma: no cover
    JSONResponse = None  # type: ignore

from ..core.engine import Guard
from ..core.model import Action, Context, Resource, Subject

EnvBuilder = Callable[[Any], Tuple[Subject, Action, Resource, Context]]

def require_access(guard: Guard, build_env: EnvBuilder, *, add_headers: bool = False):
    """Return an async callable suitable for Starlette routes."""
    async def dependency(request: Any) -> Any:
        sub, act, res, ctx = build_env(request)
        allowed = False
        if hasattr(guard, "is_allowed"):
            allowed = await guard.is_allowed(sub, act, res, ctx)  # type: ignore[attr-defined]
        elif hasattr(guard, "is_allowed_sync"):
            allowed = guard.is_allowed_sync(sub, act, res, ctx)  # type: ignore[attr-defined]
        if allowed:
            return None

        headers: Dict[str, str] = {}
        reason = None
        if add_headers:
            expl = None
            if hasattr(guard, "explain"):
                try:
                    expl = await guard.explain(sub, act, res, ctx)  # type: ignore[attr-defined]
                except Exception:  # pragma: no cover
                    expl = None
            elif hasattr(guard, "explain_sync"):
                expl = guard.explain_sync(sub, act, res, ctx)  # type: ignore[attr-defined]
            if expl is not None:
                reason = getattr(expl, "reason", None)
                rule_id = getattr(expl, "rule_id", None)
                policy_id = getattr(expl, "policy_id", None)
                if reason:
                    headers["X-RBACX-Reason"] = str(reason)
                if rule_id:
                    headers["X-RBACX-Rule"] = str(rule_id)
                if policy_id:
                    headers["X-RBACX-Policy"] = str(policy_id)

        if JSONResponse is None:
            raise RuntimeError("starlette is required for adapters.starlette")  # pragma: no cover
        return JSONResponse({"detail": "forbidden", "reason": reason}, status_code=403, headers=headers)
    return dependency
