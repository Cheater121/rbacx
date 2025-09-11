
import asyncio
import logging
import pytest

from rbacx.adapters.asgi_accesslog import AccessLogMiddleware
from rbacx.logging.context import set_current_trace_id, clear_current_trace_id

async def ok_app(scope, receive, send):
    await send({'type': 'http.response.start', 'status': 201, 'headers': []})
    await send({'type': 'http.response.body', 'body': b'ok'})

@pytest.mark.asyncio
async def test_access_log_emits(caplog):
    app = AccessLogMiddleware(ok_app)
    sent = []
    async def recv():
        return {'type': 'http.request'}
    async def send(msg):
        sent.append(msg)
    caplog.set_level(logging.INFO, logger="rbacx.adapters.asgi.access")
    scope = {'type': 'http', 'method': 'POST', 'path': '/x'}
    await app(scope, recv, send)
    # we expect a log line
    assert any("access POST /x 201" in rec.message for rec in caplog.records)
