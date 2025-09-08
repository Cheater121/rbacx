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

    def __call__(self, request):
        rid = request.META.get("HTTP_X_REQUEST_ID") or gen_trace_id()
        token = set_current_trace_id(rid)
        response = self.get_response(request)
        try:
            response["X-Request-ID"] = get_current_trace_id() or rid
        finally:
            clear_current_trace_id(token)
        return response
