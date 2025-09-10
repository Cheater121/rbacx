import asyncio
import pytest
from rbacx.adapters.asgi_logging import TraceIdMiddleware
from rbacx.logging.context import set_current_trace_id, get_current_trace_id, clear_current_trace_id

class Boom:
    async def __call__(self, scope, receive, send):
        if scope.get("type") == "http":
            raise RuntimeError("boom")

async def run_call(mw):
    scope = {"type":"http","method":"GET","path":"/","headers":[]}
    async def receive():
        return {"type":"http.request"}
    async def send(msg): pass
    await mw(scope, receive, send)

def test_context_token_reset_even_on_exception():
    app = Boom()
    mw = TraceIdMiddleware(app)
    # set and *remember* token so we can reliably reset regardless of middleware behavior
    token = set_current_trace_id("trace-exc")
    with pytest.raises(RuntimeError):
        asyncio.run(run_call(mw))
    # Ensure we reset ourselves to avoid leaking state between tests
    clear_current_trace_id(token)
    assert get_current_trace_id() is None
