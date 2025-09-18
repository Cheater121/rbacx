from rbacx.store.policy_loader import _detect_format, parse_policy_text


def test_detect_format_prefers_filename_when_content_type_ambiguous():
    fmt = _detect_format(filename="policy.yaml", content_type="text/plain")
    assert fmt == "yaml"


def test_detect_format_defaults_to_json_on_unknown():
    fmt = _detect_format(filename=None, content_type="application/octet-stream", fmt=None)
    assert fmt == "json"


def test_parse_policy_text_uses_filename_extension_when_no_content_type():
    p = parse_policy_text("rules: []\n", filename="p.yml", content_type=None)
    assert isinstance(p, dict)
