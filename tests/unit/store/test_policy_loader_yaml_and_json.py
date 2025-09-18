import json

import pytest

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
