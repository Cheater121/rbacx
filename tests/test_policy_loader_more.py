
import json
import importlib
import pytest

def _pick_loader(mod):
    # Try a few common loader names
    for name in ("load_policy", "load", "load_from_file", "load_json"):
        func = getattr(mod, name, None)
        if callable(func):
            return func
    return None

def test_load_policy_from_file(tmp_path):
    mod = importlib.import_module("rbacx.policy.loader")
    loader = _pick_loader(mod)
    if loader is None:
        pytest.skip("no loader function exported in rbacx.policy.loader")
    p = tmp_path / "p.json"
    p.write_text(json.dumps({"rules": []}), encoding="utf-8")
    pol = loader(str(p))
    assert isinstance(pol, dict)
    assert "rules" in pol
