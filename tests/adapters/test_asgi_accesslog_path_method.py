
import asyncio
import logging
from rbacx.adapters.asgi_accesslog import AccessLogMiddleware

class DummyGet:
    async def __call__(self, scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok", "more_body": False})

async def invoke(app, path="/items/42"):
    mw = AccessLogMiddleware(app)
    scope = {"type": "http", "method": "GET", "path": path, "headers": []}
    async def receive():
        return {"type": "http.request"}
    msgs = []
    async def send(m): msgs.append(m)
    await mw(scope, receive, send)
    return msgs

def test_access_log_contains_method_and_path(caplog):
    caplog.set_level(logging.INFO, logger="rbacx.adapters.asgi.access")
    asyncio.run(invoke(DummyGet(), path="/x"))
    lines = [r.getMessage() for r in caplog.records if r.name == "rbacx.adapters.asgi.access"]
    assert any("GET" in m and "/x" in m for m in lines)
