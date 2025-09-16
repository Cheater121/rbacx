import importlib
import sys
import types

import pytest


def _purge(mod: str):
    """Remove a module (and its submodules) from sys.modules to force a clean import."""
    for k in list(sys.modules):
        if k == mod or k.startswith(mod + "."):
            sys.modules.pop(k, None)


def _install_fastapi_stub(monkeypatch, *, with_http: bool = True):
    """
    Install a minimal FastAPI stub into sys.modules.

    When with_http=True, provides:
      - fastapi.HTTPException(status_code, detail=None, headers=None)
      - fastapi.Request (dummy type for type hints only)
    """
    m = types.ModuleType("fastapi")
    if with_http:

        class HTTPException(Exception):
            def __init__(self, status_code: int, detail=None, headers=None):
                super().__init__(f"{status_code}")
                self.status_code = status_code
                self.detail = detail
                self.headers = headers or {}

        class Request:  # dummy; adapter only uses it for typing
            ...

        m.HTTPException = HTTPException
        m.Request = Request

    monkeypatch.setitem(sys.modules, "fastapi", m)


class _GuardDeny:
    """Denying guard that also exposes an explanation for optional headers."""

    def __init__(self, reason="nope", rule_id="r1", policy_id="p1"):
        self.reason = reason
        self.rule_id = rule_id
        self.policy_id = policy_id

    def is_allowed_sync(self, sub, act, res, ctx):
        # Attach a last explanation like a real engine might do.
        self.last_explanation = types.SimpleNamespace(
            reason=self.reason, rule_id=self.rule_id, policy_id=self.policy_id
        )
        return False

    def get_last_explanation(self):
        return getattr(self, "last_explanation", None)


def _build_env(_req):
    """Return minimal Subject/Action/Resource/Context objects; shapes are not enforced by the adapter."""
    return object(), object(), object(), object()


@pytest.mark.parametrize("add_headers", [False, True])
def test_fastapi_require_denies_raises_http_exception_with_optional_headers(
    monkeypatch, add_headers
):
    _purge("rbacx.adapters.fastapi")
    _install_fastapi_stub(monkeypatch, with_http=True)

    import rbacx.adapters.fastapi as fa

    importlib.reload(fa)

    dep = fa.require_access(_GuardDeny(), _build_env, add_headers=add_headers)

    with pytest.raises(fa.HTTPException) as exc:
        # The dependency is expected to be called by FastAPI before the endpoint.
        dep(fa.Request())  # type: ignore

    # Must be a proper 403
    assert exc.value.status_code == 403

    # Detail is expected to be a dict (adapter may or may not pass "reason")
    assert isinstance(exc.value.detail, dict)
    assert "reason" in exc.value.detail
    # When guard explanation is available, reason can be present; otherwise None is acceptable
    assert exc.value.detail.get("reason") in (None, "nope")

    # Optional header enrichment when add_headers=True
    if add_headers:
        headers = exc.value.headers or {}
        for k in ("X-RBACX-Reason", "X-RBACX-Rule", "X-RBACX-Policy"):
            if k in headers:
                assert isinstance(headers[k], str)


def test_fastapi_require_without_fastapi_raises_runtimeerror(monkeypatch):
    """
    Force the adapter's fallback path ("no FastAPI in the environment").

    Simply popping 'fastapi' from sys.modules is not enough if FastAPI is actually installed,
    because Python will import it from disk again. To reliably exercise the fallback,
    we set rbacx.adapters.fastapi.HTTPException = None via monkeypatch so that the adapter
    raises RuntimeError as intended for this path.
    """
    _purge("rbacx.adapters.fastapi")
    sys.modules.pop("fastapi", None)  # best-effort; may be re-imported if installed

    import rbacx.adapters.fastapi as fa

    importlib.reload(fa)

    dep = fa.require_access(_GuardDeny(), _build_env, add_headers=True)

    # Force the fallback branch: pretend FastAPI's HTTPException is unavailable
    monkeypatch.setattr(fa, "HTTPException", None, raising=False)

    with pytest.raises(RuntimeError):
        dep(object())
