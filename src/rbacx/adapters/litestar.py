import logging
from typing import TYPE_CHECKING, Any, Awaitable, Callable, MutableMapping, cast

if TYPE_CHECKING:

    class _BaseMiddleware: ...

    _MODE: str = "asgi"
else:
    try:
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


# Precise ASGI callables for mypy when invoking Starlette Response
_ASGIScope = MutableMapping[str, Any]
_ASGIReceive = Callable[[], Awaitable[MutableMapping[str, Any]]]
_ASGISend = Callable[[MutableMapping[str, Any]], Awaitable[None]]


class RBACXMiddleware(_BaseMiddleware):
    """Litestar middleware that checks access using RBACX Guard.

    - Prefers :class:`litestar.middleware.ASGIMiddleware` (Litestar >= 2.15).
    - Falls back to :class:`litestar.middleware.AbstractMiddleware` when needed.
    - Uses :py:meth:`Guard.evaluate_async`.
    """

    def __init__(
        self,
        app: Any,
        *,
        guard: Guard,
        build_env: EnvBuilder,
        add_headers: bool = False,
    ) -> None:
        # AbstractMiddleware defines __init__(app) while ASGIMiddleware may not.
        try:
            super().__init__(app=app)  # type: ignore[call-arg]
        except Exception:
            self.app = app

        self.guard = guard
        self.build_env = build_env
        self.add_headers = add_headers

    async def _dispatch(self, scope: Scope, receive: Receive, send: Send) -> None:
        # Only handle HTTP scopes; pass through others
        scope_type: Any = None
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

        headers: dict[str, str] = {}
        if self.add_headers:
            if decision.reason is not None:
                headers["X-RBACX-Reason"] = str(decision.reason)
            rule_id = getattr(decision, "rule_id", None)
            if rule_id is not None:
                headers["X-RBACX-Rule"] = str(rule_id)
            policy_id = getattr(decision, "policy_id", None)
            if policy_id is not None:
                headers["X-RBACX-Policy"] = str(policy_id)

        from starlette.responses import JSONResponse  # type: ignore[import-not-found]

        res = JSONResponse({"detail": "Forbidden"}, status_code=403, headers=headers)

        # Starlette Response is an ASGI app: __call__(scope, receive, send)
        # Cast to the precise ASGI callable types expected by mypy.
        asgi_scope = cast(_ASGIScope, scope)
        asgi_receive = cast(_ASGIReceive, receive)
        asgi_send = cast(_ASGISend, send)
        await res(asgi_scope, asgi_receive, asgi_send)

    # New-style base (ASGIMiddleware) calls `handle()`
    async def handle(self, scope: Scope, receive: Receive, send: Send, next_app: Any) -> None:
        # We ignore next_app because we dispatch against self.app for both bases.
        await self._dispatch(scope, receive, send)

    # Old-style base (AbstractMiddleware) expects `__call__`
    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        await self._dispatch(scope, receive, send)
