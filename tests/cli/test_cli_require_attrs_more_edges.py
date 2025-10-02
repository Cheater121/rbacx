
from rbacx import cli

def test_parse_require_attrs_keeps_empty_entity_key_and_skips_malformed():
    s = "subject:id,org;resource:type;:a,b;MALFORMED"
    parsed = cli._parse_require_attrs(s)
    assert parsed.get("subject") == ["id", "org"]
    assert parsed.get("resource") == ["type"]
    assert parsed.get("") == ["a", "b"]
    assert "MALFORMED" not in parsed
