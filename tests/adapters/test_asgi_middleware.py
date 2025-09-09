
import asyncio
import pytest
from typing import Any

from rbacx.adapters.asgi import RbacxMiddleware


from dataclasses import dataclass
from typing import Any

@dataclass
class Decision:
    allowed: bool
    reason: str | None = None
    rule_id: str | None = None
    policy_id: str | None = None

class FakeGuard:
    def __init__(self, allowed: bool, reason: str | None = None):
        self._allowed = allowed
        self._reason = reason
    def is_allowed_sync(self, sub, act, res, ctx) -> bool:
        return self._allowed
    def evaluate_sync(self, sub, act, res, ctx) -> Decision:
        return Decision(self._allowed, self._reason)
    def explain_sync(self, sub, act, res, ctx) -> Decision:
        return Decision(self._allowed, self._reason)


async def ok_app(scope, receive, send):
    assert 'rbacx_guard' in scope
    await send({'type': 'http.response.start', 'status': 200, 'headers': []})
    await send({'type': 'http.response.body', 'body': b'OK'})

@pytest.mark.asyncio
async def test_asgi_middleware_injects_guard():
    app = RbacxMiddleware(ok_app, guard=FakeGuard(True))
    # minimal ASGI cycle
    sent = []
    async def recv():
        return {'type': 'http.request'}
    async def send(message):
        sent.append(message)
    scope = {'type': 'http', 'method': 'GET', 'path': '/'}
    await app(scope, recv, send)
    assert any(m.get('type')=='http.response.start' for m in sent)
