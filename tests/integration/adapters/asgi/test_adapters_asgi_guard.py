import asyncio
from rbacx.adapters.asgi import RbacxMiddleware
from rbacx.core.engine import Guard

class DummyASGIApp:
    def __init__(self):
        self.scope = None
        self.sent = []

    async def __call__(self, scope, receive, send):
        self.scope = scope
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

async def run_middleware():
    app = DummyASGIApp()
    mw = RbacxMiddleware(app, guard=Guard({"rules": []}), mode="inject")
    sent = []
    async def send(msg):
        sent.append(msg)
    scope = {"type": "http"}
    await mw(scope, None, send)
    return app, sent

def test_injects_guard_and_calls_app():
    app, sent = asyncio.run(run_middleware())
    from rbacx.core.engine import Guard as GuardType
    assert isinstance(app.scope.get("rbacx_guard"), GuardType)
    assert sent and sent[0].get("type") == "http.response.start"
