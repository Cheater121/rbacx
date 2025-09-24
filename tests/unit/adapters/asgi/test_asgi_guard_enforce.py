import inspect
import json

import pytest


def _find_guard_middleware(mod):
    """
    Heuristically find the guard middleware class in rbacx.adapters.asgi by
    trying to instantiate candidates with the expected signature. Returns a callable app.
    """

    def try_build(cls, inner_app):
        try:
            return cls(
                inner_app,
                guard=object(),  # will be replaced below
                build_env=lambda s: ("s", "a", "r", {"ctx": True}),
                mode="enforce",
                add_headers=True,
            )
        except Exception:
            return None

    for _name, obj in inspect.getmembers(mod, inspect.isclass):
        if obj.__module__ != mod.__name__:
            continue
        # Quick filter: must be callable (ASGI app)
        if not callable(obj):
            continue
        built = try_build(obj, lambda *_: None)
        if built is not None:
            return obj
    pytest.skip("No guard middleware class found in rbacx.adapters.asgi")


class Decision:
    def __init__(self, allowed, reason=None, rule_id=None, policy_id=None):
        self.allowed = allowed
        self.reason = reason
        self.rule_id = rule_id
        self.policy_id = policy_id


class DenyGuard:
    async def evaluate_async(self, *_a, **_k):
        return Decision(
            allowed=False,
            reason="not-allowed-by-policy",
            rule_id="rule-42",
            policy_id="policy-main",
        )


class DenyGuardNoHeaders:
    async def evaluate_async(self, *_a, **_k):
        return Decision(allowed=False, reason=None, rule_id=None, policy_id=None)


def _build_env(scope):
    return ("sub", "act", "res", {"path": scope.get("path")})


def _http_scope():
    return {
        "type": "http",
        "http_version": "1.1",
        "method": "GET",
        "path": "/deny",
        "raw_path": b"/deny",
        "headers": [(b"host", b"test")],
        "query_string": b"",
        "scheme": "http",
        "client": ("127.0.0.1", 12345),
        "server": ("testserver", 80),
    }


@pytest.mark.asyncio
async def test_enforce_deny_403_with_diagnostic_headers_and_json_body():
    """
    Covers 44-60 (deny + add_headers=True) and 72-81 (_send_json with extra_headers).
    """
    from rbacx.adapters import asgi as mod

    MW = _find_guard_middleware(mod)

    inner_called = {"flag": False}

    async def inner_app(scope, receive, send):
        inner_called["flag"] = True
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    app = MW(
        inner_app,
        guard=DenyGuard(),
        build_env=_build_env,
        mode="enforce",
        add_headers=True,
    )

    sent = []

    async def _receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def _send(message):
        sent.append(message)

    await app(_http_scope(), _receive, _send)

    # inner app must NOT run on deny
    assert inner_called["flag"] is False

    starts = [m for m in sent if m.get("type") == "http.response.start"]
    assert starts, "no http.response.start"
    start = starts[0]
    assert start["status"] == 403

    hdrs = dict(start["headers"])
    # JSON headers from _send_json
    assert hdrs[b"content-type"] == b"application/json; charset=utf-8"
    body_msg = [m for m in sent if m.get("type") == "http.response.body"][0]
    body = body_msg["body"]
    assert hdrs[b"content-length"] == str(len(body)).encode("ascii")
    # Diagnostic headers present
    assert hdrs[b"x-rbacx-reason"] == b"not-allowed-by-policy"
    assert hdrs[b"x-rbacx-rule"] == b"rule-42"
    assert hdrs[b"x-rbacx-policy"] == b"policy-main"
    # Body payload
    assert json.loads(body.decode("utf-8")) == {"detail": "Forbidden"}


@pytest.mark.asyncio
async def test_enforce_deny_without_extra_headers_branch():
    """
    Covers 44-60 (deny) and 72-81 with extra_headers absent (add_headers=False).
    """
    from rbacx.adapters import asgi as mod

    MW = _find_guard_middleware(mod)

    async def inner_app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    app = MW(
        inner_app,
        guard=DenyGuardNoHeaders(),
        build_env=_build_env,
        mode="enforce",
        add_headers=False,
    )

    sent = []

    async def _receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def _send(message):
        sent.append(message)

    await app(_http_scope(), _receive, _send)

    starts = [m for m in sent if m.get("type") == "http.response.start"]
    assert starts, "no http.response.start"
    start = starts[0]
    assert start["status"] == 403
    hdrs = dict(start["headers"])
    # must have standard JSON headers
    assert hdrs[b"content-type"] == b"application/json; charset=utf-8"
    # but NO diagnostic X-RBACX-* headers
    for k in (b"x-rbacx-reason", b"x-rbacx-rule", b"x-rbacx-policy"):
        assert k not in hdrs

    body = [m for m in sent if m.get("type") == "http.response.body"][0]["body"]
    assert json.loads(body.decode("utf-8")) == {"detail": "Forbidden"}
    assert hdrs[b"content-length"] == str(len(body)).encode("ascii")
