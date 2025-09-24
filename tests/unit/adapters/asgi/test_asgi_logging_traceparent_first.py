import pytest


@pytest.mark.asyncio
async def test_asgi_logging_uses_first_traceparent_and_sets_request_id():
    """
    Target: rbacx.adapters.asgi_logging lines 29-30.
    Case: when header name == b"traceparent" and rid is empty -> set rid to first-found value (latin1-decoded)
    and surface it via X-Request-ID in the response.
    """
    from rbacx.adapters import asgi_logging as mod

    # Most projects export the middleware as TraceIdMiddleware in this module.
    # If your project uses a different name, add it here.
    mw_cls = getattr(mod, "TraceIdMiddleware", None)
    if mw_cls is None:
        pytest.skip("TraceIdMiddleware is not exported from rbacx.adapters.asgi_logging")

    first_tp = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
    second_tp = "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-00"

    sent = []

    async def inner_app(scope, receive, send):
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"text/plain")],
            }
        )
        await send({"type": "http.response.body", "body": b"ok"})

    app = mw_cls(inner_app)

    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "GET",
        "path": "/",
        "raw_path": b"/",
        # ASGI requires lowercased byte header names and values as bytes.
        # Two traceparent headers: the middleware must keep the FIRST one it sees.
        "headers": [
            (b"traceparent", first_tp.encode("latin1")),
            (b"traceparent", second_tp.encode("latin1")),
        ],
        "query_string": b"",
        "scheme": "http",
        "client": ("127.0.0.1", 12345),
        "server": ("testserver", 80),
    }

    async def _receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def _send(message):
        sent.append(message)

    await app(scope, _receive, _send)

    # Inspect the response start headers
    starts = [m for m in sent if m.get("type") == "http.response.start"]
    assert starts, "No http.response.start message sent"
    resp_headers = dict(starts[0]["headers"])

    # The middleware should set X-Request-ID to the FIRST traceparent value (latin1 encoded)
    assert resp_headers.get(b"x-request-id") == first_tp.encode("latin1")
