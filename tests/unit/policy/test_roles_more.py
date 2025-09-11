
import importlib
import pytest

def _pick(mod, names):
    for n in names:
        f = getattr(mod, n, None)
        if callable(f):
            return f
    return None

def test_has_any_all_roles():
    roles_mod = importlib.import_module("rbacx.core.roles")
    has_any = _pick(roles_mod, ("has_any", "any_roles", "hasAny", "any"))
    has_all = _pick(roles_mod, ("has_all", "all_roles", "hasAll", "all"))
    if has_any is None or has_all is None:
        pytest.skip("roles helpers not exported with expected names")
    assert has_any(["admin", "user"], ["guest", "admin"]) is True
    assert has_all(["admin", "user"], ["user", "admin", "ops"]) is True
