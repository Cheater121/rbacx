import inspect

import pytest


def _find_guard_middleware(mod):
    """Find a guard middleware class exported by rbacx.adapters.asgi that can be instantiated with (app, guard, build_env, mode, add_headers)."""

    def can_build(cls):
        try:
            cls(
                lambda *_: None,
                guard=object(),
                build_env=lambda s: ("s", "a", "r", {"ctx": True}),
                mode="enforce",
                add_headers=True,
            )
            return True
        except Exception:
            return False

    for _, obj in inspect.getmembers(mod, inspect.isclass):
        if obj.__module__ != mod.__name__:
            continue
        if callable(obj) and can_build(obj):
            return obj
    pytest.skip("No guard middleware class found in rbacx.adapters.asgi")


class Decision:
    def __init__(self, allowed, reason=None, rule_id=None, policy_id=None):
        self.allowed = allowed
        self.reason = reason
        self.rule_id = rule_id
        self.policy_id = policy_id


class AllowGuard:
    async def evaluate_async(self, *_a, **_k):
        # Allowed=True -> take the 48->62 transition (skip deny block, call inner app)
        return Decision(allowed=True)


def _build_env(scope):
    return ("sub", "act", "res", {"path": scope.get("path")})


def _http_scope():
    return {
        "type": "http",
        "http_version": "1.1",
        "method": "GET",
        "path": "/ok",
        "raw_path": b"/ok",
        "headers": [(b"host", b"test")],
        "query_string": b"",
        "scheme": "http",
        "client": ("127.0.0.1", 12345),
        "server": ("testserver", 80),
    }


@pytest.mark.asyncio
async def test_enforce_allow_passes_through_to_inner_app():
    """
    Covers the transition 48->62 in asgi.py:
    - scope['type'] == 'http', mode == 'enforce', build_env provided -> enter block
    - decision.allowed == True -> skip deny branch and `await self.app(scope, receive, send)` (line 62).
    Expect: inner app is executed and its 200 response is sent; no X-RBACX-* headers are added.
    """
    from rbacx.adapters import asgi as mod

    MW = _find_guard_middleware(mod)

    inner_called = {"flag": False}
    sent = []

    async def inner_app(scope, receive, send):
        inner_called["flag"] = True
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"text/plain")],
            }
        )
        await send({"type": "http.response.body", "body": b"ok"})

    app = MW(
        inner_app,
        guard=AllowGuard(),
        build_env=_build_env,
        mode="enforce",
        add_headers=True,  # irrelevant when allowed=True, but ensures we enter the outer 'enforce' block
    )

    async def _receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def _send(message):
        sent.append(message)

    await app(_http_scope(), _receive, _send)

    # Must have passed through to inner app
    assert inner_called["flag"] is True

    # Check that 200 from inner app was sent (not 403 from deny)
    starts = [m for m in sent if m.get("type") == "http.response.start"]
    assert starts, "no http.response.start sent"
    assert starts[0]["status"] == 200

    # Ensure no diagnostic headers were injected on allow-path
    hdrs = dict(starts[0]["headers"])
    for k in (b"x-rbacx-reason", b"x-rbacx-rule", b"x-rbacx-policy"):
        assert k not in hdrs
