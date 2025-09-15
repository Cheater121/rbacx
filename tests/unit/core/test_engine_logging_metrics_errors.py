from rbacx.core.engine import Guard
from rbacx.core.model import Action, Context, Resource, Subject


def _policy_permit():
    return {
        "rules": [{"id": "r", "actions": ["read"], "resource": {"type": "doc"}, "effect": "permit"}]
    }


class BoomLoggerSink:
    def log(self, payload):
        raise RuntimeError("logger boom")


class BoomMetrics:
    def inc(self, *a, **k):
        raise RuntimeError("inc boom")

    def observe(self, *a, **k):
        raise RuntimeError("obs boom")


def test_engine_swallow_logger_and_metrics_errors():
    g = Guard(_policy_permit(), logger_sink=BoomLoggerSink(), metrics=BoomMetrics())
    # evaluate_sync should still succeed even if logging/metrics raise
    d = g.evaluate_sync(Subject("u", []), Action("read"), Resource("doc", "1"), Context({}))
    assert d.allowed is True
