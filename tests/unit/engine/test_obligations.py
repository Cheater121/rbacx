
from rbacx.core.obligations import BasicObligationChecker

def test_obligation_checker_permit_requires_mfa_missing():
    checker = BasicObligationChecker()
    result = {"decision": "permit", "obligations": [{"type": "require_mfa"}]}
    ok, ch = checker.check(result, context=type("Ctx", (), {"attrs": {}})())
    assert ok is False
    assert ch == "mfa"

def test_obligation_checker_permit_requires_mfa_present():
    checker = BasicObligationChecker()
    result = {"decision": "permit", "obligations": [{"type": "require_mfa"}]}
    ok, ch = checker.check(result, context=type("Ctx", (), {"attrs": {"mfa": True}})())
    assert ok is True
    assert ch is None

def test_obligation_checker_non_permit_is_false():
    checker = BasicObligationChecker()
    for decision in ["deny", None, ""]:
        ok, ch = checker.check({"decision": decision}, context=None)
        assert ok is False
        assert ch is None
