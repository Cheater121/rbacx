
import sys
import types
import builtins
import pytest
from rbacx.dsl.validate import validate_policy

def test_validate_policy_with_fake_jsonschema(tmp_path):
    policy = {"rules": []}
    fake = types.SimpleNamespace()
    called = {}
    def fake_validate(instance, schema):
        called["ok"] = True
        assert isinstance(schema, dict) and schema
        assert instance == policy
    fake.validate = fake_validate
    sys.modules["jsonschema"] = fake
    try:
        validate_policy(policy)
        assert called.get("ok") is True
    finally:
        sys.modules.pop("jsonschema", None)

def test_validate_policy_raises_when_jsonschema_missing(monkeypatch):
    real_import = builtins.__import__
    def raising_import(name, *a, **kw):
        if name == "jsonschema":
            raise ImportError("nope")
        return real_import(name, *a, **kw)
    monkeypatch.setattr(builtins, "__import__", raising_import)
    with pytest.raises(RuntimeError):
        validate_policy({"rules": []})
