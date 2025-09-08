
from rbacx.core.engine import Guard
from rbacx.core.model import Subject, Resource, Action, Context
from rbacx.core.roles import StaticRoleResolver

def test_before_after_between():
    pol = {"rules":[
        {"id":"r1","effect":"permit","actions":["read"],"resource":{"type":"doc"},"condition":{"before":[{"attr":"context.now"}, "2999-01-01T00:00:00Z"]}},
        {"id":"r2","effect":"deny","actions":["read"],"resource":{"type":"doc"}}
    ]}
    g = Guard(pol)
    d = g.evaluate_sync(Subject(id="u"), Action("read"), Resource(type="doc"), Context(attrs={"now":"2025-09-07T00:00:00Z"}))
    assert d.allowed is True

    pol2 = {"rules":[
        {"id":"r1","effect":"permit","actions":["read"],"resource":{"type":"doc"},"condition":{"between":[{"attr":"context.now"}, ["2025-01-01T00:00:00Z","2025-12-31T23:59:59Z"]]}}
    ]}
    g2 = Guard(pol2)
    d2 = g2.evaluate_sync(Subject(id="u"), Action("read"), Resource(type="doc"), Context(attrs={"now":"2025-09-07T10:00:00Z"}))
    assert d2.allowed is True

def test_role_resolver_integration():
    pol = {"rules":[
        {"id":"r","effect":"permit","actions":["read"],"resource":{"type":"doc"},"condition":{"in":[{"attr":"subject.roles"}, ["employee"]]}}
    ]}
    resolver = StaticRoleResolver({"manager":["employee"], "employee":["user"]})
    g = Guard(pol, role_resolver=resolver)
    d = g.evaluate_sync(Subject(id="u", roles=["manager"]), Action("read"), Resource(type="doc"), Context())
    assert d.allowed is True
