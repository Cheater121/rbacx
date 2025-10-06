from collections.abc import Callable
from functools import wraps
from typing import Any

try:  # Optional dependency boundary
    from flask import jsonify, request  # type: ignore[import-not-found]
except Exception:  # pragma: no cover
    jsonify = None  # type: ignore
    request = None  # type: ignore

from ..core.engine import Guard
from ._common import EnvBuilder


def require_access(
    guard: Guard, build_env: EnvBuilder, *, add_headers: bool = False
) -> Callable[..., Any]:
    """Decorator for Flask view functions to enforce access."""

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(fn)
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            """Sync-only adapter: always uses Guard.evaluate_sync."""
            if jsonify is None:  # pragma: no cover
                raise RuntimeError("flask is required for adapters.flask")

            # Use Flask's request proxy if available; builder may accept None.
            req = request if request is not None else kwargs.get("request")
            sub, act, res, ctx = build_env(req)

            decision = guard.evaluate_sync(sub, act, res, ctx)
            if decision.allowed:
                return fn(*args, **kwargs)

            # Do not leak reasons in the body. Optionally expose via headers.
            headers: dict[str, str] = {}
            if add_headers:
                if decision.reason is not None:
                    headers["X-RBACX-Reason"] = str(decision.reason)
                rule_id = getattr(decision, "rule_id", None)
                if rule_id is not None:
                    headers["X-RBACX-Rule"] = str(rule_id)
                policy_id = getattr(decision, "policy_id", None)
                if policy_id is not None:
                    headers["X-RBACX-Policy"] = str(policy_id)

            # Flask supports returning (response, status, headers) tuples.
            return jsonify({"detail": "Forbidden"}), 403, headers

        return wrapped

    return decorator
