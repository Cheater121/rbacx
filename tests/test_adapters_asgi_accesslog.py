
import asyncio
import logging
from rbacx.adapters.asgi_accesslog import AccessLogMiddleware

class DummyASGIApp:
    async def __call__(self, scope, receive, send):
        await send({"type": "http.response.start", "status": 201, "headers": []})
        await send({"type": "http.response.body", "body": b"ok", "more_body": False})

async def run_middleware():
    app = DummyASGIApp()
    mw = AccessLogMiddleware(app)
    scope = {"type": "http", "method": "POST", "path": "/items", "headers": []}
    async def receive():
        return {"type": "http.request"}
    messages = []
    async def send(msg):
        messages.append(msg)
    await mw(scope, receive, send)
    return messages

def test_access_log_emits_line(caplog):
    caplog.set_level(logging.INFO, logger="rbacx.adapters.asgi.access")
    msgs = asyncio.run(run_middleware())
    # Should have logged a line like: 'access POST /items 201 <...> trace_id=-'
    records = [r for r in caplog.records if r.name == "rbacx.adapters.asgi.access"]
    assert records, "expected access log record"
    msg = records[-1].getMessage()
    assert "access POST /items 201" in msg
    assert "trace_id=" in msg
