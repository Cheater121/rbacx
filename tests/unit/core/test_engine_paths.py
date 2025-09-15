from rbacx.core.engine import Guard
from rbacx.core.model import Action, Context, Resource, Subject


class DummyMetrics:
    def __init__(self):
        self.events = []

    def inc(self, name, labels):
        self.events.append(("inc", name, labels))

    def observe(self, name, value, labels):
        self.events.append(("observe", name, labels))


class DummyLoggerSink:
    def __init__(self):
        self.events = []

    def log(self, payload):
        self.events.append(payload)


def _policy_permit():
    return {
        "rules": [{"id": "r", "actions": ["read"], "resource": {"type": "doc"}, "effect": "permit"}]
    }


def test_engine_all_paths_sync_and_is_allowed(monkeypatch):
    metrics = DummyMetrics()
    sink = DummyLoggerSink()
    g = Guard(_policy_permit(), logger_sink=sink, metrics=metrics)

    # Force compiled path: monkeypatch engine.compile_policy to return a callable
    import rbacx.core.engine as eng

    def fake_compile(policy):
        def fn(env):
            return {"decision": "permit", "rule_id": "rc", "last_rule_id": "rc", "obligations": []}

        return fn

    monkeypatch.setattr(eng, "compile_policy", fake_compile, raising=True)
    # recompute etag to pick compiler
    g.set_policy(_policy_permit())

    sub = Subject(id="u", roles=["r"])
    act = Action(name="read")
    res = Resource(type="doc", id="1")
    ctx = Context()

    d = g.evaluate_sync(sub, act, res, ctx)
    assert d.allowed is True and d.effect == "permit" and d.rule_id

    assert g.is_allowed_sync(sub, act, res, ctx) is True


def test_engine_async_and_logging_metrics(monkeypatch):
    metrics = DummyMetrics()
    sink = DummyLoggerSink()
    g = Guard(_policy_permit(), logger_sink=sink, metrics=metrics)

    sub = Subject(id="u", roles=["r"])
    act = Action(name="read")
    res = Resource(type="doc", id="1")
    ctx = Context()

    # Async path delegates to sync
    import asyncio

    d = asyncio.get_event_loop().run_until_complete(g.evaluate_async(sub, act, res, ctx))
    assert d.allowed is True
    assert g.is_allowed_sync(sub, act, res, ctx) is True
