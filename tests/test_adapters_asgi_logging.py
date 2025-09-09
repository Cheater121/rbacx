
import asyncio
from rbacx.adapters.asgi_logging import TraceIdMiddleware
from rbacx.logging.context import get_current_trace_id

class DummyASGIApp:
    def __init__(self):
        self.sent = []

    async def __call__(self, scope, receive, send):
        # Send start and end
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok", "more_body": False})

async def run_middleware(header_name=b"x-request-id", incoming_headers=None):
    app = DummyASGIApp()
    mw = TraceIdMiddleware(app, header_name=header_name)
    scope = {"type": "http", "method": "GET", "path": "/x", "headers": incoming_headers or []}
    async def receive():
        return {"type": "http.request"}
    sent = []
    async def send(msg):
        sent.append(msg)
    await mw(scope, receive, send)
    return app, sent

def test_middleware_adds_response_header_and_clears_context():
    app, sent = asyncio.run(run_middleware())
    start_msgs = [m for m in sent if m.get("type") == "http.response.start"]
    assert start_msgs, "no start message"
    hdrs = dict((k.lower(), v) for k, v in start_msgs[-1]["headers"])
    assert b"x-request-id" in hdrs
    # After call, middleware should have cleared context
    assert get_current_trace_id() is None

def test_middleware_keeps_existing_header_name_configurable():
    app, sent = asyncio.run(run_middleware(header_name=b"x-correlation-id"))
    start_msgs = [m for m in sent if m.get("type") == "http.response.start"]
    hdrs = dict((k.lower(), v) for k, v in start_msgs[-1]["headers"])
    assert b"x-correlation-id" in hdrs
