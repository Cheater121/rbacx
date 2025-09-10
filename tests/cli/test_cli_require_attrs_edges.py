
from rbacx.cli import _parse_require_attrs

def test_parse_require_attrs_handles_spaces_and_empty():
    s = " subject : id , org ; resource : type ,  ;  ; "
    parsed = _parse_require_attrs(s)
    assert parsed.get("subject") == ["id", "org"]
    assert parsed.get("resource") == ["type"]
