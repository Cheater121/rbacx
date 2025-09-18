import json
import sys

import pytest

from rbacx.store.policy_loader import _detect_format, parse_policy_bytes, parse_policy_text


@pytest.mark.parametrize(
    "fmt,content_type,filename,expected",
    [
        ("json", None, None, "json"),  # explicit fmt wins
        ("yaml", "application/json", "x.json", "yaml"),  # explicit fmt wins over headers/ext
        (None, "application/yaml", "p.txt", "yaml"),  # content-type yaml
        (None, "application/x-yaml", None, "yaml"),  # x-yaml marker
        (None, "text/yaml; charset=utf-8", None, "yaml"),  # contains 'yaml'
        (None, "application/json", "p.yaml", "json"),  # content-type json beats ext
        (None, "application/ld+json", None, "json"),  # contains 'json'
        (None, None, "policy.yaml", "yaml"),  # extension .yaml
        (None, None, "policy.yml", "yaml"),  # extension .yml
        (None, None, "policy.json", "json"),  # extension .json
        (None, None, "policy.unknown", "json"),  # default fallback
    ],
)
def test_detect_format_ranking(fmt, content_type, filename, expected):
    assert _detect_format(fmt=fmt, content_type=content_type, filename=filename) == expected


def test_parse_policy_text_json_ok():
    text = json.dumps({"rules": [], "policies": []})
    out = parse_policy_text(text, filename="policy.json")
    assert out["rules"] == []
    assert out["policies"] == []


def test_parse_policy_text_json_invalid_raises():
    with pytest.raises(json.JSONDecodeError):
        parse_policy_text("{bad json", filename="policy.json")


def test_parse_policy_text_yaml_ok_requires_pyyaml():
    pytest.importorskip("yaml")
    text = "rules: []\n"
    out = parse_policy_text(text, filename="policy.yaml")
    assert out["rules"] == []


def test_parse_policy_text_yaml_empty_doc_becomes_empty_dict():
    pytest.importorskip("yaml")
    text = ""  # empty YAML -> None from safe_load -> {}
    out = parse_policy_text(text, filename="p.yml")
    assert out == {}


def test_parse_policy_text_yaml_top_level_must_be_mapping():
    pytest.importorskip("yaml")
    bad = "- 1\n- 2\n"
    with pytest.raises(ValueError):
        parse_policy_text(bad, filename="p.yaml")


def test_parse_policy_text_yaml_content_type_overrides_extension_to_yaml():
    pytest.importorskip("yaml")
    text = "rules: []\n"
    out = parse_policy_text(text, filename="p.json", content_type="application/x-yaml")
    assert out["rules"] == []


def test_parse_policy_text_json_content_type_overrides_extension_to_json():
    text = json.dumps({"rules": []})
    out = parse_policy_text(text, filename="p.yaml", content_type="application/json")
    assert out["rules"] == []


def test_parse_policy_text_yaml_missing_dependency_raises(monkeypatch):
    # Make 'yaml' import fail inside loader
    monkeypatch.setitem(sys.modules, "yaml", None)
    with pytest.raises(ImportError):
        parse_policy_text("rules: []\n", filename="p.yaml")


def test_parse_policy_bytes_respects_encoding_and_filename_yaml():
    pytest.importorskip("yaml")
    data = "rules: []\n".encode("utf-8")
    out = parse_policy_bytes(data, filename="policy.yml")
    assert out["rules"] == []


def test_parse_policy_bytes_respects_encoding_and_filename_json():
    data = json.dumps({"rules": []}).encode("utf-16")
    out = parse_policy_bytes(
        data, filename="policy.json", fmt=None, content_type=None, encoding="utf-16"
    )
    assert out["rules"] == []
