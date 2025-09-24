import pytest


@pytest.mark.asyncio
async def test_fastapi_dependency_sets_rbacx_headers_on_deny():
    fastapi = pytest.importorskip("fastapi")
    pytest.importorskip("starlette")

    from starlette.requests import Request

    from rbacx.adapters import fastapi as rbacx_fastapi

    class StubDecision:
        def __init__(self, allowed, reason=None, rule_id=None, policy_id=None):
            self.allowed = allowed
            self.reason = reason
            self.rule_id = rule_id
            self.policy_id = policy_id

    class StubGuard:
        def __init__(self, decision):
            self._decision = decision

        # Adapter may call either sync or async API; provide both.
        def evaluate(self, *_args, **_kwargs):
            return self._decision

        async def evaluate_async(self, *_args, **_kwargs):
            return self._decision

    decision = StubDecision(
        allowed=False,
        reason="not-allowed-by-policy",
        rule_id=None,
        policy_id="policy-main",
    )
    guard = StubGuard(decision)

    def build_env(_request):
        # Shape doesn't matter for this test; only that it's callable.
        return ("user", "action", "resource", {"ctx": True})

    dependency = rbacx_fastapi.require_access(guard, build_env, add_headers=True)

    # Minimal valid ASGI scope for Starlette Request.
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "GET",
        "path": "/",
        "raw_path": b"/",
        "headers": [],  # list[tuple[bytes, bytes]]
        "query_string": b"",
        "scheme": "http",
        "client": ("127.0.0.1", 12345),
        "server": ("testserver", 80),
    }
    request = Request(scope)

    with pytest.raises(fastapi.HTTPException) as ei:
        await dependency(request)

    exc = ei.value
    # Ensure 403 and all RBACX debug headers are present when add_headers=True
    assert exc.status_code == 403
    assert exc.headers.get("X-RBACX-Reason") == "not-allowed-by-policy"
    assert exc.headers.get("X-RBACX-Rule") is None
    assert exc.headers.get("X-RBACX-Policy") == "policy-main"
