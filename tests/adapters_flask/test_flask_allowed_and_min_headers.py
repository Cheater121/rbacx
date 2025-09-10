
from importlib import reload
import types, pytest

def _build_env(req):
    from rbacx.core.model import Subject, Action, Resource, Context
    return Subject(id="s"), Action("read"), Resource(type="doc"), Context(attrs={})

def test_flask_allowed_pass_through(monkeypatch):
    import rbacx.adapters.flask as fl
    reload(fl)
    class G:
        def is_allowed_sync(self, *a, **k): return True
        def explain_sync(self, *a, **k):
            return types.SimpleNamespace(reason="ok", rule_id="r", policy_id="p")
    try:
        import flask  # noqa: F401
        def jsonify(o): return o
        fl.jsonify = jsonify
        fn = fl.require_access(G(), _build_env, add_headers=True)(lambda: "OK")
        assert fn() == "OK"
    except Exception:
        fn = fl.require_access(G(), _build_env)(lambda: "OK")
        assert fn() == "OK"

def test_flask_denied_min_headers(monkeypatch):
    import rbacx.adapters.flask as fl
    reload(fl)
    class G:
        def is_allowed_sync(self, *a, **k): return False
        def explain_sync(self, *a, **k):
            return types.SimpleNamespace(reason="why", rule_id="r", policy_id="p")
    try:
        import flask  # noqa: F401
        def jsonify(o): return o
        fl.jsonify = jsonify
        body, status, headers = fl.require_access(G(), _build_env, add_headers=False)(lambda: None)()
        assert status == 403
        assert isinstance(headers, dict)
    except Exception:
        with pytest.raises(RuntimeError):
            fl.require_access(G(), _build_env)(lambda: None)()
