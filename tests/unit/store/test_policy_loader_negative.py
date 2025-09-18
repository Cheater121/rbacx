import json
import sys

import pytest

from rbacx.store.policy_loader import parse_policy_text


def test_yaml_requires_pyyaml_dependency(monkeypatch):
    # Ensure 'yaml' is not importable within this test to simulate missing optional dep
    monkeypatch.setitem(sys.modules, "yaml", None)
    with pytest.raises(ImportError):
        parse_policy_text("rules: []\n", filename="policy.yaml")


def test_yaml_top_level_must_be_mapping():
    pytest.importorskip("yaml")
    # A YAML sequence is not allowed at top-level by our loader
    with pytest.raises(ValueError):
        parse_policy_text("- 1\n- 2\n", filename="policy.yml")


def test_invalid_json_raises():
    with pytest.raises(json.JSONDecodeError):
        parse_policy_text("not a json", filename="policy.json")


def test_unknown_extension_defaults_to_json_and_fails_on_yaml_text():
    # We pass YAML text but unknown filename -> defaults to JSON -> JSON decode error
    with pytest.raises(json.JSONDecodeError):
        parse_policy_text("a: 1\n", filename="policy.txt")
