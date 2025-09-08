
from rbacx.core.engine import Guard
from rbacx.core.model import Subject, Resource, Action, Context

def _g(policy): return Guard(policy)

def test_deny_overrides():
    pol = {"algorithm":"deny-overrides","rules":[
        {"id":"p1","effect":"permit","actions":["read"],"resource":{"type":"doc"}},
        {"id":"d1","effect":"deny","actions":["read"],"resource":{"type":"doc"}}
    ]}
    d = _g(pol).evaluate_sync(Subject(id="u"), Action("read"), Resource(type="doc"), Context())
    assert d.allowed is False and d.effect == "deny" and d.rule_id == "d1" and d.reason == "explicit_deny"

def test_permit_overrides():
    pol = {"algorithm":"permit-overrides","rules":[
        {"id":"d1","effect":"deny","actions":["read"],"resource":{"type":"doc"}},
        {"id":"p1","effect":"permit","actions":["read"],"resource":{"type":"doc"}}
    ]}
    d = _g(pol).evaluate_sync(Subject(id="u"), Action("read"), Resource(type="doc"), Context())
    assert d.allowed is True and d.effect == "permit" and d.rule_id == "p1"

def test_no_match_reason():
    pol = {"rules":[
        {"id":"p1","effect":"permit","actions":["write"],"resource":{"type":"doc"}}
    ]}
    d = _g(pol).evaluate_sync(Subject(id="u"), Action("read"), Resource(type="doc"), Context())
    assert d.allowed is False and d.reason in {"action_mismatch","no_match"}

def test_condition_type_mismatch_reason():
    pol = {"rules":[
        {"id":"p1","effect":"permit","actions":["read"],"resource":{"type":"doc"}, "condition":{"<":[{"attr":"resource.attrs.n"}, "10"]}}
    ]}
    d = _g(pol).evaluate_sync(Subject(id="u"), Action("read"), Resource(type="doc", attrs={"n": 5}), Context())
    # since right side is string, comparison is a type mismatch => condition False with reason
    assert d.allowed is False and d.reason == "condition_type_mismatch"
