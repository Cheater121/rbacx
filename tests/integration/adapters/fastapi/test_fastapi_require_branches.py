import importlib
import sys
import types

import pytest


def _purge(modname: str) -> None:
    for k in list(sys.modules):
        if k == modname or k.startswith(modname + "."):
            sys.modules.pop(k, None)


@pytest.mark.filterwarnings("ignore::DeprecationWarning")
def test_fastapi_require_allowed_branch(monkeypatch):
    # Provide a tiny fastapi stub so the adapter imports cleanly
    class _HTTPException(Exception):
        def __init__(self, status_code: int, detail=None, headers=None):
            super().__init__(f"{status_code}: {detail!r}")
            self.status_code = status_code
            self.detail = detail
            self.headers = headers or {}

    fake_fastapi = types.ModuleType("fastapi")
    fake_fastapi.HTTPException = _HTTPException
    fake_fastapi.Request = object
    monkeypatch.setitem(sys.modules, "fastapi", fake_fastapi)

    _purge("rbacx.adapters.fastapi")
    import rbacx.adapters.fastapi as fa

    importlib.reload(fa)

    # Guard exposes only is_allowed (no *_sync) to exercise that branch
    class _GuardAllow:
        def is_allowed(self, sub, act, res, ctx):  # noqa: D401 - simple stub
            return True

    # Minimal env builder that doesn't touch real Request
    def _env(_request):
        return ("u1", "read", "doc", {"ip": "127.0.0.1"})

    dep = fa.require_access(_GuardAllow(), _env, add_headers=True)
    # Should not raise when allowed
    assert dep(object()) is None


@pytest.mark.filterwarnings("ignore::DeprecationWarning")
def test_fastapi_require_denied_explain_raises_no_headers(monkeypatch):
    # Provide a tiny fastapi stub so the adapter imports cleanly
    class _HTTPException(Exception):
        def __init__(self, status_code: int, detail=None, headers=None):
            super().__init__(f"{status_code}: {detail!r}")
            self.status_code = status_code
            self.detail = detail
            self.headers = headers or {}

    fake_fastapi = types.ModuleType("fastapi")
    fake_fastapi.HTTPException = _HTTPException
    fake_fastapi.Request = object
    monkeypatch.setitem(sys.modules, "fastapi", fake_fastapi)

    _purge("rbacx.adapters.fastapi")
    import rbacx.adapters.fastapi as fa

    importlib.reload(fa)

    class _GuardDenyExplode:
        def is_allowed(self, *_a, **_k):
            return False

        def explain(self, *_a, **_k):
            # Simulate an unexpected error inside explain() to hit the except branch
            raise RuntimeError("boom")

    def _env(_request):
        return ("u1", "write", "doc", {"ip": "127.0.0.1"})

    dep = fa.require_access(_GuardDenyExplode(), _env, add_headers=True)
    with pytest.raises(fake_fastapi.HTTPException) as exc:
        dep(object())

    # The adapter should still raise 403 with empty headers/detail when explain() fails
    assert exc.value.status_code == 403
    assert isinstance(exc.value.headers, dict) and not exc.value.headers  # no headers
    # detail can be a dict with {"reason": None} or similar — most importantly: no crash
