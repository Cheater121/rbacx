from rbacx.core.engine import Guard
from rbacx.core.model import Action, Context, Resource, Subject


class BoomMetrics:
    def inc(self, **labels):
        raise RuntimeError("boom inc")

    def observe(self, **labels):
        raise RuntimeError("boom observe")


class BoomLogger:
    def log(self, payload):
        raise RuntimeError("log failed")


def make_policy():
    return {
        "algorithm": "permit-overrides",
        "rules": [
            {"id": "r1", "actions": ["read"], "resource": {"type": "doc"}, "effect": "permit"}
        ],
    }


def test_engine_handles_metrics_and_logger_exceptions():
    g = Guard(make_policy(), metrics=BoomMetrics(), logger_sink=BoomLogger())
    d = g.evaluate_sync(Subject("u"), Action("read"), Resource("doc"), Context({}))
    assert d.allowed is True
