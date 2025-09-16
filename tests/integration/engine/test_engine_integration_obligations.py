from rbacx.core.engine import Guard
from rbacx.core.model import Action, Context, Resource, Subject


def test_engine_evaluate_sync_obligations_mfa_gate():
    policy = {
        "rules": [
            {
                "id": "p",
                "actions": ["read"],
                "effect": "permit",
                "resource": {"type": "doc"},
                "obligations": [{"type": "require_mfa"}],
            }
        ]
    }
    g = Guard(policy=policy)
    s = Subject(id="u1")
    a = Action(name="read")
    r = Resource(type="doc")
    # Without MFA in context => denied by obligation checker with challenge
    d1 = g.evaluate_sync(s, a, r, context=Context(attrs={"mfa": False}))
    assert d1.allowed is False
    assert d1.effect == "deny"
    assert d1.reason in {"obligation_failed", "obligation_not_met"}
    assert d1.challenge == "mfa"
    # With MFA => allowed
    d2 = g.evaluate_sync(s, a, r, context=Context(attrs={"mfa": True}))
    assert d2.allowed is True
    assert d2.effect == "permit"
    assert d2.challenge is None
