
import asyncio
import logging
from rbacx.adapters.asgi import RbacxMiddleware
from rbacx.core.engine import Guard

class DummyReloader:
    def __init__(self, raise_exc=False):
        self.called = 0
        self.raise_exc = raise_exc
    def check_and_reload(self):
        self.called += 1
        if self.raise_exc:
            raise RuntimeError("boom")

class DummyASGIApp:
    def __init__(self):
        self.scope = None
    async def __call__(self, scope, receive, send):
        self.scope = scope
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok", "more_body": False})

async def run_middleware(reloader=None):
    g = Guard(policy={"rules": []})
    app = DummyASGIApp()
    mw = RbacxMiddleware(app, guard=g, mode="enforce", policy_reloader=reloader)
    scope = {"type": "http", "method": "GET", "path": "/", "headers": []}
    async def receive():
        return {"type": "http.request"}
    sent = []
    async def send(m): sent.append(m)
    await mw(scope, receive, send)
    return app, sent

def test_injects_guard_and_calls_reloader(caplog):
    r = DummyReloader()
    app, sent = asyncio.run(run_middleware(r))
    from rbacx.core.engine import Guard as GuardType
    assert isinstance(app.scope.get("rbacx_guard"), GuardType)
    assert r.called == 1

def test_reloader_exception_is_logged(caplog):
    caplog.set_level(logging.ERROR, logger="rbacx.adapters.asgi")
    r = DummyReloader(raise_exc=True)
    app, sent = asyncio.run(run_middleware(r))
    # even with exception, request should succeed and be sent
    assert sent and sent[0].get("type") == "http.response.start"
    # and an exception should be logged
    assert any("policy reload failed" in rec.getMessage() for rec in caplog.records if rec.name == "rbacx.adapters.asgi")
