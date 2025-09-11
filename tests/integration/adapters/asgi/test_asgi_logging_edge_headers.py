
import asyncio
from rbacx.adapters.asgi_logging import TraceIdMiddleware

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

def _hdrs(sent):
    for m in sent:
        if m.get("type") == "http.response.start":
            return dict((k, v) for k, v in m.get("headers", []))
    return {}

def _normalize_keys(hdrs):
    out = {}
    for k, v in hdrs.items():
        if isinstance(k, (bytes, bytearray)):
            kk = k.decode().lower()
        else:
            kk = str(k).lower()
        out[kk] = v
    return out

def test_generates_new_id_if_incoming_header_empty():
    app = DummyOK()
    incoming = [(b"x-request-id", b"")]
    mw = TraceIdMiddleware(app)
    sent = asyncio.run(run_call(mw, headers=incoming))
    hdrs = _normalize_keys(_hdrs(sent))
    assert "x-request-id" in hdrs and hdrs["x-request-id"] not in (b"", None)

def test_header_name_as_str_supported_and_respected():
    app = DummyOK()
    mw = TraceIdMiddleware(app, header_name="X-Trace-ID")
    sent = asyncio.run(run_call(mw))
    hdrs = _normalize_keys(_hdrs(sent))
    assert "x-trace-id" in hdrs and hdrs["x-trace-id"]
