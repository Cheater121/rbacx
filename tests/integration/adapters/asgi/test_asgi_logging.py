
import asyncio
import pytest

from rbacx.adapters.asgi_logging import TraceIdMiddleware
from rbacx.logging.context import get_current_trace_id

async def bare_app(scope, receive, send):
    await send({'type': 'http.response.start', 'status': 200, 'headers': []})
    await send({'type': 'http.response.body', 'body': b'ok'})

@pytest.mark.asyncio
async def test_trace_id_middleware_sets_header_and_clears():
    app = TraceIdMiddleware(bare_app, header_name=b"x-request-id")
    sent = []
    async def recv():
        return {'type': 'http.request'}
    async def send(msg):
        sent.append(msg)
    scope = {'type': 'http', 'method': 'GET', 'path': '/', 'headers': []}
    assert get_current_trace_id() is None
    await app(scope, recv, send)
    # header should be present in response.start
    start = next(m for m in sent if m.get("type")=="http.response.start")
    headers = dict((k.decode().lower(), v.decode()) for k,v in start.get("headers", []))
    assert "x-request-id" in headers
    # context must be cleared after request
    assert get_current_trace_id() is None
