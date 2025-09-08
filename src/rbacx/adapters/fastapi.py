
from __future__ import annotations

from typing import Any, Callable, Dict, Tuple

try:  # Optional dependency boundary
    from fastapi import HTTPException  # type: ignore
except Exception:  # pragma: no cover
    HTTPException = None  # type: ignore

from ..core.engine import Guard
from ..core.model import Action, Context, Resource, Subject

EnvBuilder = Callable[[Any], Tuple[Subject, Action, Resource, Context]]

def require_access(guard: Guard, build_env: EnvBuilder, *, add_headers: bool = False):
    """Return a FastAPI dependency that enforces access with optional reason headers."""
    def dependency(request: Any) -> None:
        sub, act, res, ctx = build_env(request)
        # Decide
        allowed = False
        if hasattr(guard, "is_allowed_sync"):
            allowed = guard.is_allowed_sync(sub, act, res, ctx)  # type: ignore[attr-defined]
        elif hasattr(guard, "is_allowed"):
            allowed = guard.is_allowed(sub, act, res, ctx)  # type: ignore[attr-defined]
        if allowed:
            return

        headers: Dict[str, str] = {}
        reason = None
        if add_headers:
            expl = None
            if hasattr(guard, "explain_sync"):
                expl = guard.explain_sync(sub, act, res, ctx)  # type: ignore[attr-defined]
            elif hasattr(guard, "explain"):
                # best-effort sync call if available
                try:
                    expl = guard.explain(sub, act, res, ctx)  # type: ignore[attr-defined]
                except Exception:  # pragma: no cover
                    expl = None
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

        if HTTPException is None:
            raise RuntimeError("fastapi is required for adapters.fastapi")  # pragma: no cover
        raise HTTPException(status_code=403, detail={"reason": reason}, headers=headers)
    return dependency
