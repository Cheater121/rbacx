import json

from rbacx.store.policy_loader import _detect_format, parse_policy_text


def test_detect_format_unknown_fmt_falls_back_to_content_type_then_ext():
    # Unknown fmt should be ignored and content-type should decide
    assert _detect_format(fmt="xml", content_type="application/x-yaml", filename="p.json") == "yaml"
    # If content-type is absent, extension wins
    assert _detect_format(fmt="xml", content_type=None, filename="p.yaml") == "yaml"
    # If neither is present, default to json
    assert _detect_format(fmt="xml", content_type=None, filename=None) == "json"


def test_parse_policy_text_json_via_text_even_if_content_type_json():
    # Ensure parse_policy_text can accept JSON string with json content-type
    text = json.dumps({"rules": []})
    out = parse_policy_text(text, filename="p.txt", content_type="application/json", fmt=None)
    assert out["rules"] == []
