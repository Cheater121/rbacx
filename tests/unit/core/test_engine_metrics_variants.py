from rbacx.core.engine import Guard
from rbacx.core.model import Action, Context, Resource, Subject


def _policy_permit():
    return {
        "rules": [{"id": "r", "actions": ["read"], "resource": {"type": "doc"}, "effect": "permit"}]
    }


class DummyMetricsNoObserve:
    def __init__(self):
        self.calls = []

    def inc(self, name, labels):
        self.calls.append(("inc", name, labels))

    # no observe method


def test_engine_metrics_without_observe():
    g = Guard(_policy_permit(), metrics=DummyMetricsNoObserve())
    d = g.evaluate_sync(Subject("u", ["r"]), Action("read"), Resource("doc", "1"), Context({}))
    assert d.allowed is True
