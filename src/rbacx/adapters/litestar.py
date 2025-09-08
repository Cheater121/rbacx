
from __future__ import annotations

from typing import Callable

from litestar.middleware import AbstractMiddleware  # type: ignore
from litestar.types import Receive, Scope, Send  # type: ignore

from ..core.engine import Guard
from ..core.model import Action, Context, Resource, Subject


class RBACXMiddleware(AbstractMiddleware):
    """Litestar middleware that checks access using RBACX Guard.

    Configure with a function `build_env(scope) -> (Subject, Action, Resource, Context)`.
    """
    def __init__(self, app, *, guard: Guard, build_env: Callable[[Scope], tuple[Subject, Action, Resource, Context]]) -> None:
        super().__init__(app=app)
        self.guard = guard
        self.build_env = build_env

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope['type'] != 'http':
            await self.app(scope, receive, send)
            return
        subject, action, resource, context = self.build_env(scope)
        decision = await self.guard.evaluate_async(subject, action, resource, context)
        if not decision.allowed:
            # default: 403
            from starlette.responses import JSONResponse  # type: ignore
            res = JSONResponse({"detail":"forbidden","reason": decision.reason}, status_code=403)
            await res(scope, receive, send)
            return
        await self.app(scope, receive, send)
