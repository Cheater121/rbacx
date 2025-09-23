from __future__ import annotations

from functools import wraps
from typing import Any, Callable, Optional

# Optional Django imports so the module stays importable without Django
try:  # pragma: no cover
    from django.http import HttpRequest, HttpResponseForbidden  # type: ignore
except Exception:  # pragma: no cover
    HttpRequest = Any  # type: ignore
    HttpResponseForbidden = None  # type: ignore

from ...core.engine import Guard
from .._common import EnvBuilder


def require_access(
    build_env: EnvBuilder,
    *,
    guard: Optional[Guard] = None,
    add_headers: bool = False,
    audit: bool = False,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Django view decorator enforcing RBACX access (sync only).

    - If `guard` is not provided, it will be taken from `request.rbacx_guard`
      (set by RbacxDjangoMiddleware).
    - Denies with a generic 403 body; diagnostics only via headers when enabled.
    - If `audit=True`, request proceeds even when denied (soft-allow).
    """

    def decorator(view_func: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(view_func)
        def _wrapped(request: HttpRequest, *args: Any, **kwargs: Any):
            if HttpResponseForbidden is None:  # pragma: no cover
                raise RuntimeError("Django is required for adapters.django")

            # Resolve guard: explicit param takes precedence, then request attribute.
            effective_guard: Optional[Guard] = guard or getattr(request, "rbacx_guard", None)

            # Fail-closed if no guard and not auditing.
            if effective_guard is None:
                if audit:
                    return view_func(request, *args, **kwargs)
                return HttpResponseForbidden("Forbidden")

            # Build env and evaluate synchronously.
            subject, action, resource, context = build_env(request)
            decision = effective_guard.evaluate_sync(subject, action, resource, context)

            # Allow (or soft-allow in audit mode).
            if decision.allowed or audit:
                return view_func(request, *args, **kwargs)

            # Deny with generic body; optionally add diagnostic headers.
            resp = HttpResponseForbidden("Forbidden")
            if add_headers:
                if decision.reason:
                    resp["X-RBACX-Reason"] = str(decision.reason)
                rule_id = getattr(decision, "rule_id", None)
                if rule_id:
                    resp["X-RBACX-Rule"] = str(rule_id)
                policy_id = getattr(decision, "policy_id", None)
                if policy_id:
                    resp["X-RBACX-Policy"] = str(policy_id)
            return resp

        return _wrapped

    return decorator
