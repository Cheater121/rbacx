from __future__ import annotations

from typing import Any, Optional, Type

# Optional DRF imports (module must stay importable without DRF)
try:  # pragma: no cover - optional dependency
    from rest_framework.permissions import BasePermission  # type: ignore
except Exception:  # pragma: no cover
    BasePermission = None  # type: ignore

try:  # pragma: no cover - optional dependency
    from rest_framework.views import exception_handler as _drf_exception_handler  # type: ignore
except Exception:  # pragma: no cover
    _drf_exception_handler = None  # type: ignore

from ..core.engine import Guard
from ._common import EnvBuilder


def make_permission(
    guard: Guard,
    build_env: EnvBuilder,
    *,
    add_headers: bool = False,
) -> Type[BasePermission]:
    """
    Factory for a DRF permission class using RBACX Guard.

    - Sync-only: uses Guard.evaluate_sync(...)
    - Body stays generic ("Forbidden"); no reasons leaked by default.
    - If add_headers=True, denial diagnostics are stashed on request as
      `request._rbacx_denied_headers` for the exception handler to attach.
    """
    if BasePermission is None:  # pragma: no cover
        raise RuntimeError(
            "Django REST Framework is required to use rbacx.adapters.drf.make_permission()"
        )

    class RBACXPermission(BasePermission):  # type: ignore[misc]
        message = "Forbidden"

        def has_permission(self, request: Any, view: Any) -> bool:
            subject, action, resource, context = build_env(request)
            decision = guard.evaluate_sync(subject, action, resource, context)
            if decision.allowed:
                return True

            if add_headers:
                hdrs: dict[str, str] = {}
                if decision.reason:
                    hdrs["X-RBACX-Reason"] = str(decision.reason)
                rule_id = getattr(decision, "rule_id", None)
                if rule_id:
                    hdrs["X-RBACX-Rule"] = str(rule_id)
                policy_id = getattr(decision, "policy_id", None)
                if policy_id:
                    hdrs["X-RBACX-Policy"] = str(policy_id)
                # Stash for the exception handler
                request._rbacx_denied_headers = hdrs

            return False

    return RBACXPermission  # type: ignore[return-value]


def rbacx_exception_handler(exc: Exception, context: dict[str, Any]):
    """
    DRF exception handler that attaches RBACX denial headers when present.

    Add to settings:
        REST_FRAMEWORK = {
            "EXCEPTION_HANDLER": "rbacx.adapters.drf.rbacx_exception_handler",
        }
    """
    if _drf_exception_handler is None:  # pragma: no cover
        raise RuntimeError("Django REST Framework is required to use rbacx_exception_handler")

    response = _drf_exception_handler(exc, context)
    if response is not None:
        req = context.get("request")
        hdrs: Optional[dict[str, str]] = (
            getattr(req, "_rbacx_denied_headers", None) if req else None
        )
        if hdrs:
            for k, v in hdrs.items():
                # DRF Response supports header assignment directly.
                response[k] = v
    return response
