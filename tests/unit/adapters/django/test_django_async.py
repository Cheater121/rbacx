"""Unit tests for async Django adapter components.

Tests use lightweight stubs — Django itself is not required to run them.
"""

import asyncio
from unittest.mock import MagicMock

import pytest

from rbacx import Action, Context, Guard, Resource, Subject

# ---------------------------------------------------------------------------
# Stubs (avoid Django install requirement)
# ---------------------------------------------------------------------------


class _FakeRequest:
    """Minimal Django HttpRequest stub."""

    def __init__(self, guard=None, headers=None, meta=None):
        if guard is not None:
            self.rbacx_guard = guard
        self.headers = headers or {}
        self.META = meta or {}


class _FakeResponse:
    def __init__(self, body="OK", status=200):
        self.body = body
        self.status = status
        self._headers: dict[str, str] = {}

    def __setitem__(self, key, value):
        self._headers[key] = value

    def __getitem__(self, key):
        return self._headers[key]


class _FakeForbidden(_FakeResponse):
    def __init__(self, body="Forbidden"):
        super().__init__(body, 403)


# ---------------------------------------------------------------------------
# Patch Django optional imports inside the modules under test
# ---------------------------------------------------------------------------


def _patch_django_imports(monkeypatch):
    """Make HttpRequest / HttpResponseForbidden available in the decorators module."""
    import rbacx.adapters.django.decorators as dec_mod

    monkeypatch.setattr(dec_mod, "HttpRequest", _FakeRequest, raising=False)
    monkeypatch.setattr(dec_mod, "HttpResponseForbidden", _FakeForbidden, raising=False)


def _patch_middleware_imports(monkeypatch):
    """Make settings available in the middleware module."""
    import rbacx.adapters.django.middleware as mw_mod

    fake_settings = MagicMock()
    fake_settings.RBACX_GUARD_FACTORY = None
    monkeypatch.setattr(mw_mod, "settings", fake_settings, raising=False)


# ---------------------------------------------------------------------------
# Shared policy / guard
# ---------------------------------------------------------------------------

_POLICY_PERMIT = {
    "algorithm": "deny-overrides",
    "rules": [
        {"id": "r-permit", "effect": "permit", "actions": ["read"], "resource": {"type": "doc"}},
    ],
}
_POLICY_DENY = {
    "algorithm": "deny-overrides",
    "rules": [
        {"id": "r-deny", "effect": "deny", "actions": ["read"], "resource": {"type": "doc"}},
    ],
}

_S = Subject(id="u1")
_R = Resource(type="doc", id="d1")
_CTX = Context()


def build_env(request):
    """Shared EnvBuilder used across decorator tests."""
    return _S, Action("read"), _R, _CTX


def _build_env(request):
    return _S, Action("read"), _R, _CTX


# ---------------------------------------------------------------------------
# async_require_access — permit
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_async_require_access_permits(monkeypatch):
    """Permitted request calls through to the view."""
    _patch_django_imports(monkeypatch)
    from rbacx.adapters.django.decorators import async_require_access

    guard = Guard(_POLICY_PERMIT)
    request = _FakeRequest(guard=guard)

    @async_require_access(_build_env)
    async def view(req):
        return _FakeResponse("ok")

    resp = await view(request)
    assert resp.body == "ok"


# ---------------------------------------------------------------------------
# async_require_access — deny
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_async_require_access_denies(monkeypatch):
    """Denied request returns 403 without calling the view."""
    _patch_django_imports(monkeypatch)
    from rbacx.adapters.django.decorators import async_require_access

    guard = Guard(_POLICY_DENY)
    request = _FakeRequest(guard=guard)
    view_called = []

    @async_require_access(_build_env)
    async def view(req):
        view_called.append(True)
        return _FakeResponse("ok")

    resp = await view(request)
    assert isinstance(resp, _FakeForbidden)
    assert not view_called


# ---------------------------------------------------------------------------
# async_require_access — add_headers
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_async_require_access_add_headers(monkeypatch):
    """add_headers=True populates X-RBACX-* on the 403 response."""
    _patch_django_imports(monkeypatch)
    from rbacx.adapters.django.decorators import async_require_access

    guard = Guard(_POLICY_DENY)
    request = _FakeRequest(guard=guard)

    @async_require_access(_build_env, add_headers=True)
    async def view(req):
        return _FakeResponse("ok")

    resp = await view(request)
    assert isinstance(resp, _FakeForbidden)
    assert resp._headers.get("X-RBACX-Rule") == "r-deny"


# ---------------------------------------------------------------------------
# async_require_access — audit mode
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_async_require_access_audit_mode_allows_deny(monkeypatch):
    """audit=True passes the request through even when denied."""
    _patch_django_imports(monkeypatch)
    from rbacx.adapters.django.decorators import async_require_access

    guard = Guard(_POLICY_DENY)
    request = _FakeRequest(guard=guard)

    @async_require_access(_build_env, audit=True)
    async def view(req):
        return _FakeResponse("ok")

    resp = await view(request)
    assert resp.body == "ok"


# ---------------------------------------------------------------------------
# async_require_access — no guard fail-closed
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_async_require_access_no_guard_fail_closed(monkeypatch):
    """No guard and audit=False returns 403 (fail-closed)."""
    _patch_django_imports(monkeypatch)
    from rbacx.adapters.django.decorators import async_require_access

    request = _FakeRequest()  # no rbacx_guard

    @async_require_access(_build_env)
    async def view(req):
        return _FakeResponse("ok")

    resp = await view(request)
    assert isinstance(resp, _FakeForbidden)


@pytest.mark.asyncio
async def test_async_require_access_no_guard_audit_allows(monkeypatch):
    """No guard but audit=True still calls the view."""
    _patch_django_imports(monkeypatch)
    from rbacx.adapters.django.decorators import async_require_access

    request = _FakeRequest()

    @async_require_access(_build_env, audit=True)
    async def view(req):
        return _FakeResponse("ok")

    resp = await view(request)
    assert resp.body == "ok"


# ---------------------------------------------------------------------------
# async_require_access — explicit guard overrides request guard
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_async_require_access_explicit_guard_overrides(monkeypatch):
    """Explicit guard= parameter takes precedence over request.rbacx_guard."""
    _patch_django_imports(monkeypatch)
    from rbacx.adapters.django.decorators import async_require_access

    # Request carries a permit guard, but decorator uses a deny guard
    request = _FakeRequest(guard=Guard(_POLICY_PERMIT))

    @async_require_access(_build_env, guard=Guard(_POLICY_DENY))
    async def view(req):
        return _FakeResponse("ok")

    resp = await view(request)
    assert isinstance(resp, _FakeForbidden)


# ---------------------------------------------------------------------------
# AsyncRbacxDjangoMiddleware
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_async_middleware_attaches_guard(monkeypatch):
    """AsyncRbacxDjangoMiddleware attaches guard to request.rbacx_guard."""
    _patch_middleware_imports(monkeypatch)
    from rbacx.adapters.django.middleware import AsyncRbacxDjangoMiddleware

    guard = Guard(_POLICY_PERMIT)
    seen = {}

    async def get_response(request):
        seen["guard"] = getattr(request, "rbacx_guard", None)
        return _FakeResponse()

    mw = AsyncRbacxDjangoMiddleware(get_response)
    mw._guard = guard  # inject directly, bypassing factory

    request = _FakeRequest()
    await mw(request)

    assert seen["guard"] is guard


@pytest.mark.asyncio
async def test_async_middleware_no_guard_does_not_set_attr(monkeypatch):
    """AsyncRbacxDjangoMiddleware without a guard does not set rbacx_guard."""
    _patch_middleware_imports(monkeypatch)
    from rbacx.adapters.django.middleware import AsyncRbacxDjangoMiddleware

    async def get_response(request):
        return _FakeResponse()

    mw = AsyncRbacxDjangoMiddleware(get_response)
    # _guard stays None (no factory configured)

    request = _FakeRequest()
    await mw(request)

    assert not hasattr(request, "rbacx_guard")


def test_async_middleware_flags():
    """AsyncRbacxDjangoMiddleware declares correct async/sync capability flags."""
    from rbacx.adapters.django.middleware import AsyncRbacxDjangoMiddleware

    assert AsyncRbacxDjangoMiddleware.async_capable is True
    assert AsyncRbacxDjangoMiddleware.sync_capable is False


def test_async_middleware_sets_is_coroutine_marker(monkeypatch):
    """_is_coroutine marker is set when get_response is a coroutine function."""
    _patch_middleware_imports(monkeypatch)
    from rbacx.adapters.django.middleware import AsyncRbacxDjangoMiddleware

    async def get_response(request):
        return _FakeResponse()

    mw = AsyncRbacxDjangoMiddleware(get_response)
    assert hasattr(mw, "_is_coroutine")
    assert mw._is_coroutine is asyncio.coroutines._is_coroutine


def test_async_middleware_no_is_coroutine_for_sync_get_response(monkeypatch):
    """_is_coroutine marker is NOT set when get_response is synchronous."""
    _patch_middleware_imports(monkeypatch)
    from rbacx.adapters.django.middleware import AsyncRbacxDjangoMiddleware

    def get_response(request):
        return _FakeResponse()

    mw = AsyncRbacxDjangoMiddleware(get_response)
    assert not hasattr(mw, "_is_coroutine")


# ---------------------------------------------------------------------------
# AsyncTraceIdMiddleware
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_async_trace_middleware_adds_request_id_header():
    """AsyncTraceIdMiddleware sets X-Request-ID on the response."""
    from rbacx.adapters.django.trace import AsyncTraceIdMiddleware

    async def get_response(request):
        return _FakeResponse()

    mw = AsyncTraceIdMiddleware(get_response)
    request = _FakeRequest(headers={"X-Request-ID": "test-id-123"})
    resp = await mw(request)
    assert resp._headers.get("X-Request-ID") == "test-id-123"


@pytest.mark.asyncio
async def test_async_trace_middleware_generates_uuid_when_no_header():
    """AsyncTraceIdMiddleware generates a UUID when no id header is present."""
    from rbacx.adapters.django.trace import AsyncTraceIdMiddleware

    async def get_response(request):
        return _FakeResponse()

    mw = AsyncTraceIdMiddleware(get_response)
    request = _FakeRequest()
    resp = await mw(request)
    rid = resp._headers.get("X-Request-ID", "")
    assert rid and rid != ""  # some id was generated


@pytest.mark.asyncio
async def test_async_trace_middleware_accepts_traceparent():
    """AsyncTraceIdMiddleware falls back to the traceparent header."""
    from rbacx.adapters.django.trace import AsyncTraceIdMiddleware

    async def get_response(request):
        return _FakeResponse()

    mw = AsyncTraceIdMiddleware(get_response)
    request = _FakeRequest(headers={"traceparent": "00-abc123-def456-01"})
    resp = await mw(request)
    assert resp._headers.get("X-Request-ID") == "00-abc123-def456-01"


def test_async_trace_middleware_flags():
    """AsyncTraceIdMiddleware declares correct async/sync capability flags."""
    from rbacx.adapters.django.trace import AsyncTraceIdMiddleware

    assert AsyncTraceIdMiddleware.async_capable is True
    assert AsyncTraceIdMiddleware.sync_capable is False


# ---------------------------------------------------------------------------
# Coverage gaps — decorators.py lines 121→123, 124→126, 128
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_async_require_access_add_headers_no_reason(monkeypatch):
    """add_headers=True but decision.reason is None — X-RBACX-Reason not set
    (transition 121→123)."""
    _patch_django_imports(monkeypatch)
    from rbacx.adapters.django.decorators import async_require_access

    # Policy with no_match → reason="no_match", rule_id=None, policy_id=None
    policy_no_match = {
        "algorithm": "deny-overrides",
        "rules": [
            {"id": "r1", "effect": "permit", "actions": ["write"], "resource": {"type": "doc"}},
        ],
    }
    guard = Guard(policy_no_match)
    request = _FakeRequest(guard=guard)

    @async_require_access(build_env, add_headers=True)
    async def view(req):
        return _FakeResponse("ok")

    resp = await view(request)
    assert isinstance(resp, _FakeForbidden)
    # reason is "no_match" (truthy) so Reason header IS set
    # rule_id is None → X-RBACX-Rule NOT set (transition 124→126)
    assert "X-RBACX-Rule" not in resp._headers
    # policy_id is None → X-RBACX-Policy NOT set
    assert "X-RBACX-Policy" not in resp._headers


@pytest.mark.asyncio
async def test_async_require_access_add_headers_with_policy_id(monkeypatch):
    """add_headers=True with a policyset decision that has policy_id set —
    X-RBACX-Policy header is populated (line 128)."""
    _patch_django_imports(monkeypatch)
    from rbacx.adapters.django.decorators import async_require_access

    policyset = {
        "algorithm": "deny-overrides",
        "policies": [
            {
                "id": "p1",
                "algorithm": "deny-overrides",
                "rules": [
                    {
                        "id": "r-deny",
                        "effect": "deny",
                        "actions": ["read"],
                        "resource": {"type": "doc"},
                    },
                ],
            }
        ],
    }
    guard = Guard(policyset)
    request = _FakeRequest(guard=guard)

    @async_require_access(build_env, add_headers=True)
    async def view(req):
        return _FakeResponse("ok")

    resp = await view(request)
    assert isinstance(resp, _FakeForbidden)
    assert resp._headers.get("X-RBACX-Policy") == "p1"


# ---------------------------------------------------------------------------
# Coverage gap — middleware.py lines 98-99 (factory_path is not None)
# ---------------------------------------------------------------------------


def test_async_middleware_loads_guard_from_factory(monkeypatch):
    """AsyncRbacxDjangoMiddleware calls RBACX_GUARD_FACTORY when configured
    (lines 98-99)."""
    import rbacx.adapters.django.middleware as mw_mod

    expected_guard = Guard(_POLICY_PERMIT)
    factory_called = []

    def fake_factory():
        factory_called.append(True)
        return expected_guard

    fake_settings = MagicMock()
    fake_settings.RBACX_GUARD_FACTORY = "myapp.build_guard"
    monkeypatch.setattr(mw_mod, "settings", fake_settings, raising=False)
    monkeypatch.setattr(mw_mod, "_load_dotted", lambda path: fake_factory, raising=False)

    async def get_response(req):
        return _FakeResponse()

    mw = mw_mod.AsyncRbacxDjangoMiddleware(get_response)
    assert factory_called == [True]
    assert mw._guard is expected_guard


# ---------------------------------------------------------------------------
# Coverage gap — trace.py 63→exit (sync get_response → no _is_coroutine)
# ---------------------------------------------------------------------------


def test_async_trace_middleware_no_is_coroutine_for_sync_get_response():
    """_is_coroutine is NOT set when get_response is a regular function
    (transition 63→exit in AsyncTraceIdMiddleware.__init__)."""
    from rbacx.adapters.django.trace import AsyncTraceIdMiddleware

    def sync_get_response(request):
        return _FakeResponse()

    mw = AsyncTraceIdMiddleware(sync_get_response)
    assert not hasattr(mw, "_is_coroutine")


@pytest.mark.asyncio
async def test_async_require_access_add_headers_empty_reason(monkeypatch):
    """add_headers=True but decision.reason is falsy (empty string or None) —
    X-RBACX-Reason must NOT be set (transition 121→123 in async_require_access)."""
    _patch_django_imports(monkeypatch)
    from rbacx.adapters.django.decorators import async_require_access
    from rbacx.core.decision import Decision

    # Patch Guard.evaluate_async to return a Decision with reason=""
    async def fake_evaluate_async(self, subject, action, resource, context=None, *, explain=False):
        return Decision(allowed=False, effect="deny", reason="", rule_id=None, policy_id=None)

    monkeypatch.setattr(Guard, "evaluate_async", fake_evaluate_async)

    guard = Guard(_POLICY_DENY)
    request = _FakeRequest(guard=guard)

    @async_require_access(build_env, add_headers=True)
    async def view(req):
        return _FakeResponse("ok")

    resp = await view(request)
    assert isinstance(resp, _FakeForbidden)
    assert "X-RBACX-Reason" not in resp._headers
