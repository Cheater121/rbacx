import pytest

from rbacx.adapters.asgi_logging import TraceIdMiddleware


@pytest.mark.asyncio
async def test_trace_id_loop_branch_false_then_true_sets_header_from_request():
    """
    First header does not match (false branch -> loop continues),
    second header is x-request-id (true branch -> break).
    This exercises the 24->23 arc in coverage for the loop condition.
    """
    messages = []

    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        messages.append(message)

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        # Important: first a non-matching header, then the correct one
        "headers": [
            (b"host", b"example.test"),  # if -> False, arc 24->23 back to 'for'
            (b"x-request-id", b"abc-123"),  # if -> True, break
        ],
        "query_string": b"",
    }

    mw = TraceIdMiddleware(app)
    await mw(scope, receive, send)

    # Response should include the same X-Request-ID taken from the request
    start = next(m for m in messages if m.get("type") == "http.response.start")
    hdrs = dict((k.lower(), v) for k, v in start.get("headers", []))
    assert hdrs[b"x-request-id"] == b"abc-123"


@pytest.mark.asyncio
async def test_trace_id_loop_branch_only_non_matching_generates_and_sets_header():
    """
    No x-request-id header is present; the loop takes the false branch,
    the middleware generates a new trace id and sets it on the response.
    """
    messages = []

    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        messages.append(message)

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [
            (b"host", b"example.test"),  # non-matching header, triggers false branch
        ],
        # intentionally omit query_string to vary code path
    }

    mw = TraceIdMiddleware(app)
    await mw(scope, receive, send)

    start = next(m for m in messages if m.get("type") == "http.response.start")
    hdrs = dict((k.lower(), v) for k, v in start.get("headers", []))
    # X-Request-ID must be present and non-empty
    assert b"x-request-id" in hdrs
    assert isinstance(hdrs[b"x-request-id"], (bytes, bytearray))
    assert len(hdrs[b"x-request-id"]) > 0
