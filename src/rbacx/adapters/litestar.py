from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Dict

# Try the modern base first (Litestar >= 2.15), then fallback to the legacy one.
if TYPE_CHECKING:
    # During type checking we don't want mypy to see multiple incompatible bases
    # rebound into the same _BaseMiddleware name.
    class _BaseMiddleware(object):  # minimal base for typing only
        ...

    _MODE: str = "asgi"
else:
    try:  # pragma: no cover
        from litestar.middleware import (
            ASGIMiddleware as _BaseMiddleware,  # type: ignore[import-not-found]
        )

        _MODE = "asgi"
    except Exception:  # pragma: no cover
        try:
            from litestar.middleware import (
                AbstractMiddleware as _BaseMiddleware,  # type: ignore[import-not-found]
            )

            _MODE = "abstract"
        except Exception:  # pragma: no cover
            _BaseMiddleware = object  # type: ignore[assignment]
            _MODE = "none"

try:  # pragma: no cover
    from litestar.types import Receive, Scope, Send  # type: ignore[import-not-found]
except Exception:  # pragma: no cover
    from typing import Any as Receive  # type: ignore
    from typing import Any as Scope  # type: ignore
    from typing import Any as Send  # type: ignore

from ..core.engine import Guard
from ._common import EnvBuilder

logger = logging.getLogger(__name__)


class RBACXMiddleware(_BaseMiddleware):
    """Litestar middleware that checks access using RBACX Guard.

    - Prefers :class:`litestar.middleware.ASGIMiddleware` (Litestar >= 2.15).
    - Falls back to :class:`litestar.middleware.AbstractMiddleware` when needed.
    - Uses :py:meth:`Guard.evaluate_async`.
    """

    def __init__(
        self,
        app,
        *,
        guard: Guard,
        build_env: EnvBuilder,
        add_headers: bool = False,
    ) -> None:
        # AbstractMiddleware defines __init__(app) while ASGIMiddleware may not.
        try:
            # works for AbstractMiddleware
            super().__init__(app=app)  # type: ignore[call-arg]
        except Exception:
            self.app = app  # ASGIMiddleware or no-base fallback

        self.guard = guard
        self.build_env = build_env
        self.add_headers = add_headers

    async def _dispatch(self, scope: Scope, receive: Receive, send: Send) -> None:
        # Only handle HTTP scopes; pass through others
        scope_type = None
        try:
            scope_type = scope.get("type")  # type: ignore[attr-defined]
        except Exception:
            logger.debug("scope.get('type') failed; treating as non-http", exc_info=True)

        if scope_type != "http":
            await self.app(scope, receive, send)  # type: ignore[arg-type]
            return

        subject, action, resource, context = self.build_env(scope)
        decision = await self.guard.evaluate_async(subject, action, resource, context)
        if decision.allowed:
            await self.app(scope, receive, send)  # type: ignore[arg-type]
            return

        # Deny: keep body generic; optionally expose diagnostics via headers
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

        from starlette.responses import JSONResponse  # type: ignore[import-not-found]

        res = JSONResponse({"detail": "Forbidden"}, status_code=403, headers=headers)
        await res(scope, receive, send)

    # New-style base (ASGIMiddleware) calls `handle()`
    async def handle(self, scope: Scope, receive: Receive, send: Send):  # type: ignore[override]
        return await self._dispatch(scope, receive, send)

    # Old-style base (AbstractMiddleware) expects `__call__`
    async def __call__(self, scope: Scope, receive: Receive, send: Send):  # type: ignore[override]
        return await self._dispatch(scope, receive, send)
