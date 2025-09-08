
from __future__ import annotations

import logging
from typing import Any

from ..core.engine import Guard

logger = logging.getLogger("rbacx.adapters.asgi")

class RbacxMiddleware:
    def __init__(self, app: Any, *, guard: Guard, mode: str = "enforce", policy_reloader: Any | None = None) -> None:
        self.app = app
        self.guard = guard
        self.mode = mode
        self.reloader = policy_reloader

    async def __call__(self, scope, receive, send):
        if self.reloader:
            try:
                self.reloader.check_and_reload()
            except Exception as e:
                logger.exception("RBACX: policy reload failed", exc_info=e)
        scope["rbacx_guard"] = self.guard
        await self.app(scope, receive, send)
