from __future__ import annotations

from typing import Dict

try:  # Optional dependency boundary
    from litestar.connection import ASGIConnection  # type: ignore[import-not-found]
    from litestar.exceptions import PermissionDeniedException  # type: ignore[import-not-found]
    from litestar.handlers.base import BaseRouteHandler  # type: ignore[import-not-found]
except Exception:  # pragma: no cover
    ASGIConnection = object  # type: ignore
    BaseRouteHandler = object  # type: ignore
    PermissionDeniedException = None  # type: ignore

from ..core.engine import Guard
from ._common import EnvBuilder


def require_access(
    guard: Guard,
    build_env: EnvBuilder,
    *,
    add_headers: bool = False,
    audit: bool = False,
):
    """Litestar guard factory enforcing access with RBACX Guard."""

    async def checker(connection: ASGIConnection, _handler: BaseRouteHandler) -> None:
        """Async-only guard: always uses Guard.evaluate_async."""
        if PermissionDeniedException is None:  # pragma: no cover
            raise RuntimeError("litestar is required for adapters.litestar")

        subject, action, resource, context = build_env(connection)
        decision = await guard.evaluate_async(subject, action, resource, context)

        # Allow if permitted, or soft-allow when audit=True.
        if decision.allowed or audit:
            return

        # Do not leak reasons in the body; optionally surface via headers.
        headers: Dict[str, str] = {}
        if add_headers:
            if decision.reason:
                headers["X-RBACX-Reason"] = str(decision.reason)
            rule_id = getattr(decision, "rule_id", None)
            if rule_id:
                headers["X-RBACX-Rule"] = str(rule_id)
            policy_id = getattr(decision, "policy_id", None)
            if policy_id:
                headers["X-RBACX-Policy"] = str(policy_id)

        # Raise standard 403 guard exception; Litestar will serialize it.
        # PermissionDeniedException supports custom headers.
        raise PermissionDeniedException(detail="Forbidden", headers=headers or None)

    return checker
