from __future__ import annotations

import contextvars
import uuid
from logging import Filter
from typing import Optional

_trace_id: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "rbacx_trace_id", default=None
)


def set_current_trace_id(value: str) -> contextvars.Token:
    return _trace_id.set(value)


def get_current_trace_id() -> Optional[str]:
    return _trace_id.get()


def clear_current_trace_id(token: contextvars.Token | None = None) -> None:
    if token is not None:
        _trace_id.reset(token)
    else:
        _trace_id.set(None)


def gen_trace_id() -> str:
    return str(uuid.uuid4())


class TraceIdFilter(Filter):
    def filter(self, record) -> bool:
        record.trace_id = get_current_trace_id() or "-"
        return True
