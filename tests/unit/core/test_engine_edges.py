
from types import SimpleNamespace
from rbacx.core.engine import Guard

class BadMetrics:
    def inc(self, *a, **k): raise RuntimeError("x")
    def observe(self, *a, **k): raise RuntimeError("y")

class BadLogger:
    def log(self, *a, **k): raise RuntimeError("z")

class RaisingResolver:
    def expand(self, roles): raise RuntimeError("boom")

def test_engine_metrics_logging_error_paths_and_etag():
    policy = {"rules":[{"effect":"permit","actions":["read"],"resource":{"type":"*"}}]}
    g = Guard(policy, logger_sink=BadLogger(), metrics=BadMetrics())
    sub = SimpleNamespace(id="u", roles=["r"], attrs=None)
    act = SimpleNamespace(name="read")
    res = SimpleNamespace(type="doc", id=None, attrs=None)
    ctx = SimpleNamespace(attrs={})
    d = g.evaluate_sync(sub, act, res, ctx)
    assert d.allowed in (True, False)
    # role resolver raising shouldn't break
    g2 = Guard(policy, role_resolver=RaisingResolver())
    d2 = g2.evaluate_sync(sub, act, res, ctx)
    assert d2.allowed in (True, False)
