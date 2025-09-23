from __future__ import annotations

from typing import Callable

from ...logging.context import (
    clear_current_trace_id,
    gen_trace_id,
    get_current_trace_id,
    set_current_trace_id,
)


class TraceIdMiddleware:
    def __init__(self, get_response: Callable) -> None:
        self.get_response = get_response
        self.req_header = "X-Request-ID"  # canonical request id header
        self.w3c_header = "traceparent"  # optional W3C Trace Context

    def __call__(self, request):
        # Prefer Django's case-insensitive headers mapping (Django ≥ 2.2); fallback to META.
        rid = getattr(request, "headers", {}).get(self.req_header) or request.META.get(
            "HTTP_X_REQUEST_ID"
        )

        # (Optional) accept W3C trace context if no X-Request-ID present
        if not rid:
            rid = getattr(request, "headers", {}).get(self.w3c_header) or request.META.get(
                "HTTP_TRACEPARENT"
            )

        if not rid:
            rid = gen_trace_id()

        token = set_current_trace_id(rid)
        response = self.get_response(request)
        try:
            # Set the id back on the response (clients/logs can correlate)
            response["X-Request-ID"] = get_current_trace_id() or rid
            # (Optional) also echo W3C header if you consumed it upstream
            # response["traceparent"] = response["X-Request-ID"]
        finally:
            clear_current_trace_id(token)
        return response
