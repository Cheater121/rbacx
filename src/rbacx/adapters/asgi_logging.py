from __future__ import annotations

import logging
from typing import Any

from ..logging.context import clear_current_trace_id, gen_trace_id, set_current_trace_id

logger = logging.getLogger("rbacx.adapters.asgi")


class TraceIdMiddleware:
    def __init__(self, app: Any, header_name: bytes = b"x-request-id") -> None:
        self.app = app
        self.header_name = header_name.lower()  # normalize once

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        req_headers = scope.get("headers", []) or []
        rid = None
        for k, v in req_headers:
            k = k.lower()
            if k == self.header_name:
                rid = v.decode("latin1")
                break
            # optional: accept W3C trace context too
            if k == b"traceparent" and not rid:  # keep first-found
                rid = v.decode("latin1")  # or parse to extract trace-id part

        if not rid:
            rid = gen_trace_id()

        token = set_current_trace_id(rid)

        async def send_wrapper(message):
            if message.get("type") == "http.response.start":
                headers = message.setdefault("headers", [])
                try:
                    # remove any existing header to avoid duplicates
                    headers[:] = [h for h in headers if h[0].lower() != self.header_name]
                    headers.append((self.header_name, rid.encode("latin1")))  # tuple of bytes
                except Exception:
                    logger.debug("TraceIdMiddleware: failed to set response header", exc_info=True)
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            clear_current_trace_id(token)
