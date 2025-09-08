
from rbacx.core.engine import Guard
from rbacx.core.model import Subject, Resource, Action, Context

def test_hasAll_hasAny():
    pol = {"rules":[
        {"id":"r1","effect":"permit","actions":["read"],"resource":{"type":"doc"},
         "condition":{"hasAll":[{"attr":"subject.roles"}, ["editor","user"]]}},
        {"id":"r2","effect":"permit","actions":["read"],"resource":{"type":"doc"},
         "condition":{"hasAny":[{"attr":"subject.roles"}, ["auditor","viewer"]]}},
    ]}
    g = Guard(pol)
    d1 = g.evaluate_sync(Subject(id="u", roles=["editor","user"]), Action("read"), Resource(type="doc"), Context())
    assert d1.allowed is True
    d2 = g.evaluate_sync(Subject(id="u", roles=["viewer"]), Action("read"), Resource(type="doc"), Context())
    assert d2.allowed is True
