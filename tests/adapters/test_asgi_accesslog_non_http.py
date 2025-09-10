
import asyncio
import logging
from rbacx.adapters.asgi_accesslog import AccessLogMiddleware

class Dummy:
    async def __call__(self, scope, receive, send):
        # do nothing for non-http
        if scope.get("type") == "http":
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"ok", "more_body": False})

async def invoke(scope):
    app = Dummy()
    mw = AccessLogMiddleware(app)
    async def receive():
        return {"type": "lifespan.startup"}
    sent = []
    async def send(m): sent.append(m)
    await mw(scope, receive, send)
    return sent

def test_non_http_scope_does_not_log(caplog):
    caplog.set_level(logging.INFO, logger="rbacx.adapters.asgi.access")
    # websocket scope should not trigger the http access logger by our middleware
    asyncio.run(invoke({"type":"websocket", "path":"/ws"}))
    lines = [r for r in caplog.records if r.name == "rbacx.adapters.asgi.access"]
    assert not lines
