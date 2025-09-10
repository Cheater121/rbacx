
import asyncio
import logging
from rbacx.adapters.asgi_accesslog import AccessLogMiddleware
from rbacx.logging.context import set_current_trace_id, clear_current_trace_id

class Dummy201:
    async def __call__(self, scope, receive, send):
        await send({"type": "http.response.start", "status": 201, "headers": []})
        await send({"type": "http.response.body", "body": b"ok", "more_body": False})

class Dummy404:
    async def __call__(self, scope, receive, send):
        await send({"type": "http.response.start", "status": 404, "headers": []})
        await send({"type": "http.response.body", "body": b"no", "more_body": False})

async def invoke(app):
    mw = AccessLogMiddleware(app)
    scope = {"type": "http", "method": "GET", "path": "/x", "headers": []}
    async def receive():
        return {"type": "http.request"}
    msgs = []
    async def send(m): msgs.append(m)
    await mw(scope, receive, send)
    return msgs

def test_access_log_contains_trace_id_and_status_201(caplog):
    caplog.set_level(logging.INFO, logger="rbacx.adapters.asgi.access")
    set_current_trace_id("tid-1")
    try:
        asyncio.run(invoke(Dummy201()))
        recs = [r for r in caplog.records if r.name == "rbacx.adapters.asgi.access"]
        assert recs
        msg = recs[-1].getMessage()
        assert "201" in msg and "trace_id=tid-1" in msg
    finally:
        clear_current_trace_id()

def test_access_log_works_for_404(caplog):
    caplog.set_level(logging.INFO, logger="rbacx.adapters.asgi.access")
    asyncio.run(invoke(Dummy404()))
    recs = [r for r in caplog.records if r.name == "rbacx.adapters.asgi.access"]
    assert recs and "404" in recs[-1].getMessage()
