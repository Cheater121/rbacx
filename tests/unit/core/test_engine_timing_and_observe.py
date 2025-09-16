from rbacx.core.engine import Guard
from rbacx.core.model import Action, Context, Resource, Subject


def _policy_permit():
    return {
        "rules": [{"id": "r", "actions": ["read"], "resource": {"type": "doc"}, "effect": "permit"}]
    }


class MetricsWithObserve:
    def __init__(self):
        self.calls = []

    def inc(self, *a, **k):
        self.calls.append(("inc", a, k))

    def observe(self, *a, **k):
        self.calls.append(("observe", a, k))


def test_engine_observe_called_and_no_crash():
    m = MetricsWithObserve()
    g = Guard(_policy_permit(), metrics=m)
    d = g.evaluate_sync(Subject("u", []), Action("read"), Resource("doc", "1"), Context({}))
    assert d.allowed is True
    # at least one inc and one observe should be attempted
    kinds = [c[0] for c in m.calls]
    assert "inc" in kinds
    assert "observe" in kinds
