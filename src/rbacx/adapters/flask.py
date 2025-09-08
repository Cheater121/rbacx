
from __future__ import annotations

from typing import Any, Callable, Dict, Tuple

try:  # Optional dependency boundary
    from flask import jsonify  # type: ignore
except Exception:  # pragma: no cover
    jsonify = None  # type: ignore

from ..core.engine import Guard
from ..core.model import Action, Context, Resource, Subject

EnvBuilder = Callable[[Any], Tuple[Subject, Action, Resource, Context]]

def require_access(guard: Guard, build_env: EnvBuilder, *, add_headers: bool = False):
    """Decorator for Flask view functions to enforce access."""
    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        def wrapped(*args: Any, **kwargs: Any):
            # Expect request as first arg (Flask passes none; the builder decides)
            request = kwargs.get("request") if "request" in kwargs else (args[0] if args else None)
            sub, act, res, ctx = build_env(request)
            allowed = False
            if hasattr(guard, "is_allowed_sync"):
                allowed = guard.is_allowed_sync(sub, act, res, ctx)  # type: ignore[attr-defined]
            elif hasattr(guard, "is_allowed"):
                allowed = guard.is_allowed(sub, act, res, ctx)  # type: ignore[attr-defined]
            if allowed:
                return fn(*args, **kwargs)

            headers: Dict[str, str] = {}
            reason = None
            if add_headers and hasattr(guard, "explain_sync"):
                expl = guard.explain_sync(sub, act, res, ctx)  # type: ignore[attr-defined]
                reason = getattr(expl, "reason", None)
                rule_id = getattr(expl, "rule_id", None)
                policy_id = getattr(expl, "policy_id", None)
                if reason:
                    headers["X-RBACX-Reason"] = str(reason)
                if rule_id:
                    headers["X-RBACX-Rule"] = str(rule_id)
                if policy_id:
                    headers["X-RBACX-Policy"] = str(policy_id)

            if jsonify is None:
                raise RuntimeError("flask is required for adapters.flask")  # pragma: no cover
            return jsonify({"detail": "forbidden", "reason": reason}), 403, headers
        return wrapped
    return decorator
