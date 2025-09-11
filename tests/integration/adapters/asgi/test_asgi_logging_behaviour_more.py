import asyncio
import pytest
from rbacx.adapters.asgi_logging import TraceIdMiddleware
from rbacx.logging.context import get_current_trace_id

class DummyOK:
    async def __call__(self, scope, receive, send):
        if scope.get("type") == "http":
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"ok", "more_body": False})

async def run_call(mw, scope=None, headers=None):
    scope = scope or {"type": "http", "method": "GET", "path": "/", "headers": headers or []}
    sent = []
    async def receive():
        return {"type": "http.request"}
    async def send(msg):
        sent.append(msg)
    await mw(scope, receive, send)
    return sent

def extract_headers(start_msg):
    return {k.lower(): v for k, v in start_msg.get("headers", [])}

def test_sets_default_header_when_absent_and_clears_context():
    app = DummyOK()
    mw = TraceIdMiddleware(app)  # defaults to x-request-id
    sent = asyncio.run(run_call(mw))
    start = [m for m in sent if m["type"] == "http.response.start"][-1]
    hdrs = extract_headers(start)
    assert b"x-request-id" in hdrs and hdrs[b"x-request-id"]
    # context must be cleared after request
    assert get_current_trace_id() is None

def test_respects_custom_header_name_and_keeps_existing_value():
    app = DummyOK()
    mw = TraceIdMiddleware(app, header_name=b"x-correlation-id")
    incoming = [(b"x-correlation-id", b"abc-123")]
    sent = asyncio.run(run_call(mw, headers=incoming))
    start = [m for m in sent if m["type"] == "http.response.start"][-1]
    hdrs = extract_headers(start)
    # header exists and is not empty; middleware should not remove it
    assert hdrs.get(b"x-correlation-id") == b"abc-123"

def test_non_http_scope_is_pass_through():
    # ASGI apps may receive non-http scopes (e.g., websocket); middleware should not crash
    app = DummyOK()
    mw = TraceIdMiddleware(app)
    scope = {"type": "websocket", "path": "/ws"}
    sent = asyncio.run(run_call(mw, scope=scope))
    # our DummyOK doesn't emit HTTP messages for non-http scope
    assert all(m.get("type") != "http.response.start" for m in sent)
