import sys
import types

import pytest


# Minimal ASGI JSONResponse stub
class StubJSONResponse:
    def __init__(self, data, status_code=200, headers=None):
        self.data = data
        self.status_code = status_code
        self.headers = headers or {}

    async def __call__(self, scope, receive, send):
        asgi_headers = []
        for k, v in self.headers.items():
            asgi_headers.append((str(k).lower().encode("latin1"), str(v).encode("latin1")))
        await send(
            {"type": "http.response.start", "status": self.status_code, "headers": asgi_headers}
        )
        await send({"type": "http.response.body", "body": b""})


def _install_jsonresponse_stub(monkeypatch):
    mod = types.SimpleNamespace(JSONResponse=StubJSONResponse)
    monkeypatch.setitem(sys.modules, "starlette.responses", mod)


def _http_scope():
    return {
        "type": "http",
        "http_version": "1.1",
        "method": "GET",
        "path": "/",
        "raw_path": b"/",
        "headers": [(b"host", b"test")],
        "query_string": b"",
        "scheme": "http",
        "client": ("127.0.0.1", 12345),
        "server": ("testserver", 80),
    }


@pytest.mark.asyncio
async def test_non_http_scope_attribute_error_pass_through_and_logs_debug(monkeypatch):
    """
    Covers lines 56-61 updated: raising on scope.get('type') triggers logger.debug(..., exc_info=True),
    then the middleware treats it as non-HTTP and passes through to inner app.
    """
    _install_jsonresponse_stub(monkeypatch)
    from rbacx.adapters import litestar as mod

    # Inject a stub logger to capture debug calls
    class LoggerStub:
        def __init__(self):
            self.calls = []

        def debug(self, *args, **kwargs):
            self.calls.append((args, kwargs))

    logger_stub = LoggerStub()
    monkeypatch.setattr(mod, "logger", logger_stub, raising=False)

    from rbacx.adapters.litestar import RBACXMiddleware

    class WeirdScope:
        def get(self, *_a, **_k):
            raise RuntimeError("boom")

    inner_called = {"flag": False}

    async def inner_app(scope, receive, send):
        inner_called["flag"] = True
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    class Guard:
        async def evaluate_async(self, *_a, **_k):
            pytest.fail("guard should not be called for non-http scopes")

    def build_env(_s):
        pytest.fail("build_env should not be called for non-http scopes")

    mw = RBACXMiddleware(inner_app, guard=Guard(), build_env=build_env, add_headers=True)

    sent = []

    async def _receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def _send(message):
        sent.append(message)

    await mw(WeirdScope(), _receive, _send)

    # Inner app was called (passthrough)
    assert inner_called["flag"] is True
    starts = [m for m in sent if m.get("type") == "http.response.start"]
    assert starts and starts[0]["status"] == 200

    # logger.debug was called once with exc_info=True
    assert len(logger_stub.calls) == 1
    args, kwargs = logger_stub.calls[0]
    assert "scope.get('type') failed" in args[0]
    assert kwargs.get("exc_info") is True


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "reason, rule_id, policy_id, expected",
    [
        ("r", None, None, {b"x-rbacx-reason": b"r"}),
        (None, "rule-1", None, {b"x-rbacx-rule": b"rule-1"}),
        (None, None, "pol-1", {b"x-rbacx-policy": b"pol-1"}),
        (None, None, None, {}),
    ],
)
async def test_deny_headers_matrix_add_headers_true(
    monkeypatch, reason, rule_id, policy_id, expected
):
    """
    Covers 73-78 transitions (reason branch) and 79-83 branches (rule_id / policy_id).
    """
    _install_jsonresponse_stub(monkeypatch)
    from rbacx.adapters.litestar import RBACXMiddleware

    class Decision:
        def __init__(self, allowed, reason=None, rule_id=None, policy_id=None):
            self.allowed = allowed
            self.reason = reason
            self.rule_id = rule_id
            self.policy_id = policy_id

    class Guard:
        async def evaluate_async(self, *_a, **_k):
            return Decision(False, reason=reason, rule_id=rule_id, policy_id=policy_id)

    def build_env(scope):
        return ("s", "a", "r", {"p": scope.get("path")})

    mw = RBACXMiddleware(lambda *_: None, guard=Guard(), build_env=build_env, add_headers=True)

    sent = []

    async def _receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def _send(message):
        sent.append(message)

    await mw(_http_scope(), _receive, _send)

    starts = [m for m in sent if m.get("type") == "http.response.start"]
    assert starts and starts[0]["status"] == 403
    hdrs = dict(starts[0]["headers"])
    diag = {k: v for k, v in hdrs.items() if k.startswith(b"x-rbacx-")}
    assert diag == expected


@pytest.mark.asyncio
async def test_handle_delegates_to_dispatch_and_allows_path(monkeypatch):
    """
    Covers 89-91: handle(...) delegates to _dispatch, and allowed path passes through.
    """
    _install_jsonresponse_stub(monkeypatch)
    from rbacx.adapters.litestar import RBACXMiddleware

    class Decision:
        def __init__(self, allowed):
            self.allowed = allowed

    inner_called = {"flag": False}

    async def inner_app(scope, receive, send):
        inner_called["flag"] = True
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    class Guard:
        async def evaluate_async(self, *_a, **_k):
            return Decision(True)

    def build_env(scope):
        return ("s", "a", "r", {})

    mw = RBACXMiddleware(inner_app, guard=Guard(), build_env=build_env, add_headers=True)

    sent = []

    async def _receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def _send(message):
        sent.append(message)

    await mw.handle(_http_scope(), _receive, _send)

    assert inner_called["flag"] is True
    starts = [m for m in sent if m.get("type") == "http.response.start"]
    assert starts and starts[0]["status"] == 200
