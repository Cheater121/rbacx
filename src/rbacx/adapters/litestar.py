from __future__ import annotations

from typing import Dict

from litestar.middleware import AbstractMiddleware
from litestar.types import Receive, Scope, Send

from ..core.engine import Guard
from ._common import EnvBuilder


class RBACXMiddleware(AbstractMiddleware):
    """Litestar middleware that checks access using RBACX Guard.

    Configure with a function `build_env(scope) -> (Subject, Action, Resource, Context)`.
    """

    def __init__(
        self,
        app,
        *,
        guard: Guard,
        build_env: EnvBuilder,
        add_headers: bool = False,
    ) -> None:
        super().__init__(app=app)
        self.guard = guard
        self.build_env = build_env
        self.add_headers = add_headers

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        # Only handle HTTP scopes; pass through others (e.g., websockets)
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        subject, action, resource, context = self.build_env(scope)
        decision = await self.guard.evaluate_async(subject, action, resource, context)
        if decision.allowed:
            await self.app(scope, receive, send)
            return

        # Do not leak reasons in the body; optionally add diagnostic headers.
        headers: Dict[str, str] = {}
        if self.add_headers:
            if decision.reason:
                headers["X-RBACX-Reason"] = str(decision.reason)
            rule_id = getattr(decision, "rule_id", None)
            if rule_id:
                headers["X-RBACX-Rule"] = str(rule_id)
            policy_id = getattr(decision, "policy_id", None)
            if policy_id:
                headers["X-RBACX-Policy"] = str(policy_id)

        # Starlette responses are valid ASGI apps and work fine in Litestar middleware.
        from starlette.responses import JSONResponse  # type: ignore[import-not-found]

        res = JSONResponse({"detail": "Forbidden"}, status_code=403, headers=headers)
        await res(scope, receive, send)  # type: ignore[arg-type]
