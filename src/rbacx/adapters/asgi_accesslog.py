import logging
import time
from typing import Any

from ..logging.context import get_current_trace_id

logger = logging.getLogger("rbacx.adapters.asgi.access")


class AccessLogMiddleware:
    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        method = scope.get("method")
        path = (scope.get("path") or "") + (
            ("?" + scope.get("query_string", b"").decode("latin1"))
            if scope.get("query_string")
            else ""
        )
        start = time.time()
        status = 0

        async def send_wrapper(message: dict) -> None:
            nonlocal status
            if message.get("type") == "http.response.start":
                status = int(message.get("status", 0))
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            dur_ms = int((time.time() - start) * 1000)
            rid = get_current_trace_id() or "-"
            logger.info(
                "access %s %s %s %sms trace_id=%s",
                method,
                path,
                status,
                dur_ms,
                rid,
            )
