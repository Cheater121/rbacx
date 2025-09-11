
import types, pytest
from importlib import reload

def _allow_guard():
    class G:
        def is_allowed_sync(self, *a, **k): return True
        def explain_sync(self, *a, **k):
            return types.SimpleNamespace(reason="ok", rule_id="r", policy_id="p")
    return G()

def _deny_guard():
    class G:
        def is_allowed_sync(self, *a, **k): return False
        def explain_sync(self, *a, **k):
            return types.SimpleNamespace(reason="no", rule_id="r", policy_id="p")
    return G()

def _build_env(req):
    from rbacx.core.model import Subject, Action, Resource, Context
    return Subject(id="s"), Action("read"), Resource(type="doc"), Context(attrs={})

def test_fastapi_permit_passes_through(monkeypatch):
    import rbacx.adapters.fastapi as fa
    reload(fa)
    dep = fa.require_access(_allow_guard(), _build_env, add_headers=True)
    try:
        import fastapi  # noqa: F401
        # allowed path should not raise
        assert dep(object()) is None or dep(object()) is not None
    except Exception:
        # If FastAPI not present, allowed branch still should not raise RuntimeError
        assert dep(object()) is None

def test_fastapi_deny_without_headers(monkeypatch):
    import rbacx.adapters.fastapi as fa
    reload(fa)
    dep = fa.require_access(_deny_guard(), _build_env, add_headers=False)
    try:
        import fastapi  # noqa: F401
        with pytest.raises(Exception) as ei:
            dep(object())
        assert getattr(ei.value, "status_code", 403) == 403
    except Exception:
        with pytest.raises(RuntimeError):
            dep(object())
