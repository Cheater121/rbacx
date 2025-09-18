import pytest

from rbacx.adapters.asgi_logging import TraceIdMiddleware


class DummyApp:
    async def __call__(self, scope, receive, send):
        # Simulate sending a response.start with immutable headers (tuple)
        await send({"type": "http.response.start", "headers": (b"h", b"v")})
        await send({"type": "http.response.body", "body": b"ok"})


@pytest.mark.asyncio
async def test_trace_id_middleware_handles_header_mutation_error():
    app = TraceIdMiddleware(DummyApp(), header_name=b"x-request-id")
    sent = []

    async def send(msg):
        sent.append(msg)

    scope = {"type": "http", "headers": []}

    async def dummy_receive():
        return {}

    await app(scope, dummy_receive, send)
    # We should still get both messages forwarded despite the header processing error
    assert any(m.get("type") == "http.response.start" for m in sent)
    # And middleware should not crash; header may or may not be present due to tuple immutability
