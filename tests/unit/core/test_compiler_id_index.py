
from rbacx.core.engine import Guard
from rbacx.core.model import Subject, Resource, Action, Context

def test_id_specific_rule_wins_over_wildcard():
    pol = {"algorithm":"permit-overrides","rules":[
        {"id":"wild","effect":"permit","actions":["read"],"resource":{"type":"doc"}},     # generic
        {"id":"specific","effect":"deny","actions":["read"],"resource":{"type":"doc","id":"A"}}
    ]}
    d = Guard(pol).evaluate_sync(Subject(id="u"), Action("read"), Resource(type="doc", id="A"), Context())
    assert d.allowed is False and d.rule_id == "specific"
