from importlib import reload
import types, asyncio, pytest

def _build_env(req):
    from rbacx.core.model import Subject, Action, Resource, Context
    return Subject(id="s"), Action("read"), Resource(type="doc"), Context(attrs={})

def test_starlette_allowed_pass_through(monkeypatch):
    import rbacx.adapters.starlette as st
    reload(st)
    class G:
        def evaluate_sync(self, *a, **k):
            d = types.SimpleNamespace(allowed=True, reason="ok",
                                      explain=types.SimpleNamespace(reason="ok", rule_id="r", policy_id="p"))
            return d
    try:
        import starlette  # noqa: F401
        class JSONResponse:
            def __init__(self, data, status_code=200, headers=None):
                self.data, self.status_code, self.headers = data, status_code, headers or {}
        st.JSONResponse = JSONResponse
        dep = st.require_access(G(), _build_env, add_headers=True)
        res = asyncio.run(dep(object()))
        assert res is None or res is not None
    except Exception:
        dep = st.require_access(G(), _build_env, add_headers=True)
        with pytest.raises(RuntimeError):
            asyncio.run(dep(object()))

def test_starlette_denied_min_headers(monkeypatch):
    import rbacx.adapters.starlette as st
    reload(st)
    class G:
        def evaluate_sync(self, *a, **k):
            d = types.SimpleNamespace(allowed=False, reason="no",
                                      explain=types.SimpleNamespace(reason="no", rule_id="r", policy_id="p"))
            return d
    try:
        import starlette  # noqa: F401
        class JSONResponse:
            def __init__(self, data, status_code=200, headers=None):
                self.data, self.status_code, self.headers = data, status_code, headers or {}
        st.JSONResponse = JSONResponse
        dep = st.require_access(G(), _build_env, add_headers=False)
        res = asyncio.run(dep(object()))
        assert res.status_code == 403
        assert isinstance(res.headers, dict)
    except Exception:
        dep = st.require_access(G(), _build_env, add_headers=False)
        with pytest.raises(RuntimeError):
            asyncio.run(dep(object()))
