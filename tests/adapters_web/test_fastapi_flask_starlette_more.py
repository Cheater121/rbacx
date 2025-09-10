from importlib import reload
import types, asyncio, pytest

def _build_env(req):
    from rbacx.core.model import Subject, Action, Resource, Context
    return Subject(id="s"), Action("read"), Resource(type="doc"), Context(attrs={})

def _fake_guard_result(allowed, reason=""):
    return types.SimpleNamespace(allowed=allowed, reason=reason,
                                 explain=types.SimpleNamespace(reason=reason, rule_id="r", policy_id="p"))

def test_starlette_require_access_runtime_and_json(monkeypatch):
    import rbacx.adapters.starlette as st
    reload(st)
    class G:
        def evaluate_sync(self, *a, **k):
            return _fake_guard_result(False, reason="no")
    try:
        import starlette  # noqa: F401
        class JSONResponse:
            def __init__(self, data, status_code=200, headers=None):
                self.data, self.status_code, self.headers = data, status_code, headers or {}
        st.JSONResponse = JSONResponse
        dep = st.require_access(G(), _build_env, add_headers=True)
        resp = asyncio.run(dep(object()))
        assert resp.status_code == 403
        assert isinstance(resp.headers, dict)
    except Exception:
        dep = st.require_access(G(), _build_env, add_headers=True)
        with pytest.raises(RuntimeError):
            asyncio.run(dep(object()))
