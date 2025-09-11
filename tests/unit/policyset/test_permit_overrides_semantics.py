
from rbacx.core.engine import Guard
from rbacx.core.model import Subject, Resource, Action, Context

def test_permit_overrides_allows_permit_even_if_deny_first():
    pol = {"algorithm":"permit-overrides","rules":[
        {"id":"deny1","effect":"deny","actions":["read"],"resource":{"type":"doc"}},
        {"id":"permit1","effect":"permit","actions":["read"],"resource":{"type":"doc"}}
    ]}
    g = Guard(pol)
    d = g.evaluate_sync(Subject(id="u"), Action("read"), Resource(type="doc"), Context())
    assert d.allowed is True and d.rule_id == "permit1"
