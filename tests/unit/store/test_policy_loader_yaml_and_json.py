import json

import pytest

from rbacx.store import policy_loader as pl
from rbacx.store.policy_loader import parse_policy_text


def test_parse_policy_text_json_by_extension(tmp_path):
    p = tmp_path / "policy.json"
    p.write_text(json.dumps({"rules": []}), encoding="utf-8")
    data = parse_policy_text(p.read_text(encoding="utf-8"), filename=str(p))
    assert isinstance(data, dict)
    assert data.get("rules") == []


def test_parse_policy_text_yaml_by_extension(tmp_path):
    pytest.importorskip("yaml")
    p = tmp_path / "policy.yaml"
    p.write_text("rules: []\n", encoding="utf-8")
    data = parse_policy_text(p.read_text(encoding="utf-8"), filename=str(p))
    assert isinstance(data, dict)
    assert data.get("rules") == []


def test_parse_policy_text_yaml_by_content_type():
    pytest.importorskip("yaml")
    text = "rules: []\n"
    data = parse_policy_text(text, filename="policy.unknown", content_type="application/x-yaml")
    assert data.get("rules") == []


def test_parse_policy_text_json_fallback_without_hints():
    text = '{"rules": []}'
    data = parse_policy_text(text)
    assert data.get("rules") == []


def test_content_type_json_true_branch():
    # Hit the JSON path inside the Content-Type block:
    # - content_type present
    # - YAML check is False
    # - JSON check is True -> returns "json"
    out = pl.parse_policy_text('{"k":"v"}', content_type="application/json")
    assert out == {"k": "v"}


def test_content_type_both_checks_false_then_extension_json():
    # Exercise the path where both YAML/JSON checks under Content-Type are False,
    # then we fall through to the filename extension logic and still get JSON.
    out = pl.parse_policy_text("{}", content_type="text/plain", filename="policy.json")
    assert out == {}
