
from rbacx.core.engine import Guard
from rbacx.core.model import Subject, Resource, Action, Context

def test_first_applicable_order_preserved_with_indexing():
    # first rule non-matching type, second permit matches, third deny broader but later
    pol = {"algorithm":"first-applicable","rules":[
        {"id":"r0","effect":"permit","actions":["read"],"resource":{"type":"image"}},
        {"id":"r1","effect":"permit","actions":["read"],"resource":{"type":"doc"}},
        {"id":"r2","effect":"deny","actions":["read"],"resource":{"type":"*"}}
    ]}
    d = Guard(pol).evaluate_sync(Subject(id="u"), Action("read"), Resource(type="doc"), Context())
    assert d.allowed is True and d.rule_id == "r1"
