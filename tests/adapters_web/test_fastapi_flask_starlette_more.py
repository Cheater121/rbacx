
import sys, types, pytest
from importlib import reload
import asyncio

def _fake_guard_result(allowed=False, reason="nope", rule="r1", policy="p1"):
    class D: pass
    d = D()
    d.allowed = allowed
    d.reason = reason
    d.explain = types.SimpleNamespace(reason=reason, rule_id=rule, policy_id=policy)
    return d

def _build_env(req):
    from rbacx.core.model import Subject, Action, Resource, Context
    return Subject(id="s"), Action("read"), Resource(type="doc"), Context(attrs={})

def test_fastapi_require_access_builds_headers_without_fastapi():
    import rbacx.adapters.fastapi as fa
    reload(fa)
    class G:
        def evaluate_sync(self, *a, **k): return _fake_guard_result(False)
    dep = fa.require_access(G(), _build_env, add_headers=True)
    try:
        import fastapi  # noqa: F401
        with pytest.raises(Exception) as ei:
            dep(object())
        e = ei.value
        assert getattr(e, "status_code", 403) == 403
    except Exception:
        with pytest.raises(RuntimeError):
            dep(object())

def test_fastapi_require_access_with_fake_http_exception(monkeypatch):
    import rbacx.adapters.fastapi as fa
    reload(fa)
    class HTTPExc(Exception):
        def __init__(self, status_code, detail=None, headers=None):
            super().__init__(status_code, detail, headers)
            self.status_code = status_code
            self.detail = detail
            self.headers = headers or {}
    fa.HTTPException = HTTPExc
    class G:
        def evaluate_sync(self, *a, **k): return _fake_guard_result(False, reason="X", rule="RID", policy="PID")
    dep = fa.require_access(G(), _build_env, add_headers=True)
    with pytest.raises(HTTPExc) as ei:
        dep(object())
    e = ei.value
    assert e.status_code == 403
    assert isinstance(e.headers, dict)

def test_flask_require_access_runtime_and_json(monkeypatch):
    import rbacx.adapters.flask as fl
    reload(fl)
    class G:
        def evaluate_sync(self, *a, **k): return _fake_guard_result(False, reason="why")
    try:
        import flask  # noqa: F401
        def jsonify(obj): return obj
        fl.jsonify = jsonify
        body, status, headers = fl.require_access(G(), _build_env, add_headers=True)(lambda: None)()
        assert status == 403
        assert isinstance(headers, dict)
    except Exception:
        with pytest.raises(RuntimeError):
            fl.require_access(G(), _build_env)(lambda: None)()

def test_starlette_require_access_runtime_and_json(monkeypatch):
    import rbacx.adapters.starlette as st
    reload(st)
    class G:
        def evaluate_sync(self, *a, **k): return _fake_guard_result(False, reason="no")
    try:
        import starlette  # noqa: F401
        class JSONResponse:
            def __init__(self, data, status_code=200, headers=None):
                self.data, self.status_code, self.headers = data, status_code, headers or {}
        st.JSONResponse = JSONResponse
        dep = st.require_access(G(), _build_env, add_headers=True)
        # dependency is async; run it
        resp = asyncio.run(dep(object()))
        assert resp.status_code == 403
        assert isinstance(resp.headers, dict)
    except Exception:
        with pytest.raises(RuntimeError):
            st.require_access(G(), _build_env)(object())
