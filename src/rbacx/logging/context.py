import contextvars
import uuid
from logging import Filter, LogRecord

_trace_id: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "rbacx_trace_id", default=None
)


def set_current_trace_id(value: str) -> contextvars.Token[str | None]:
    return _trace_id.set(value)


def get_current_trace_id() -> str | None:
    return _trace_id.get()


def clear_current_trace_id(token: contextvars.Token[str | None] | None = None) -> None:
    if token is not None:
        _trace_id.reset(token)
    else:
        _trace_id.set(None)


def gen_trace_id() -> str:
    return str(uuid.uuid4())


class TraceIdFilter(Filter):
    def filter(self, record: LogRecord) -> bool:
        record.trace_id = get_current_trace_id() or "-"
        return True
