import json
from concurrent.futures import ThreadPoolExecutor

from rbacx.core.cache import AbstractCache, DefaultInMemoryCache
from rbacx.core.engine import Guard
from rbacx.core.model import Action, Context, Resource, Subject


def _policy_permit():
    return {
        "rules": [{"id": "r", "actions": ["read"], "resource": {"type": "doc"}, "effect": "permit"}]
    }


class SpyDeciderGuard(Guard):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.decide_calls = 0

    async def _decide_async(self, env):
        self.decide_calls += 1
        # minimal raw result
        return {"decision": "permit", "obligations": [], "policy_id": "p", "reason": None}


class FakeCache(AbstractCache):
    def __init__(self):
        self.store = {}
        self.get_calls = 0
        self.set_calls = 0
        self.clear_calls = 0

    def get(self, key: str):
        self.get_calls += 1
        v = self.store.get(key)
        return v

    def set(self, key: str, value, ttl=None):
        self.set_calls += 1
        self.store[key] = value

    def delete(self, key: str):
        self.store.pop(key, None)

    def clear(self):
        self.clear_calls += 1
        self.store.clear()


def _env(subject_attrs=None, context_attrs=None):
    # helper to construct the env structure used by Guard
    subject_attrs = subject_attrs or {}
    context_attrs = context_attrs or {}
    return {
        "subject": {"id": "u", "roles": [], "attrs": subject_attrs},
        "action": "read",
        "resource": {"type": "doc", "id": "1", "attrs": {}},
        "context": context_attrs,
    }


def test_cache_key_uses_policy_etag_and_env_deterministic():
    g = Guard(_policy_permit())
    env1 = _env(subject_attrs={"a": 1, "b": 2})
    env2 = _env(subject_attrs={"b": 2, "a": 1})  # different order
    k1 = g._cache_key(env1)
    k2 = g._cache_key(env2)
    assert k1 and k2 and k1 == k2

    # changing a value should change the key
    env3 = _env(subject_attrs={"a": 1, "b": 3})
    k3 = g._cache_key(env3)
    assert k3 != k1


def test_cache_hit_returns_cached_raw_decision(monkeypatch):
    g = SpyDeciderGuard(_policy_permit(), cache=DefaultInMemoryCache())
    # build the same env that evaluate will create
    env = _env()
    key = g._cache_key(env)
    assert key
    g.cache.set(key, {"decision": "permit", "obligations": [], "policy_id": "p", "reason": None})
    d = g.evaluate_sync(Subject("u", []), Action("read"), Resource("doc", "1"), Context({}))
    assert d.allowed is True
    # _decide_async was NOT called due to cache hit
    assert g.decide_calls == 0


def test_cache_miss_computes_and_sets():
    fc = FakeCache()
    g = SpyDeciderGuard(_policy_permit(), cache=fc)
    d1 = g.evaluate_sync(Subject("u", []), Action("read"), Resource("doc", "1"), Context({}))
    assert d1.allowed is True
    assert g.decide_calls == 1
    # second call with same env should be cached
    d2 = g.evaluate_sync(Subject("u", []), Action("read"), Resource("doc", "1"), Context({}))
    assert d2.allowed is True
    assert g.decide_calls == 1  # no additional compute
    assert fc.set_calls >= 1
    assert fc.get_calls >= 1


def test_guard_respects_cache_ttl(monkeypatch):
    g = SpyDeciderGuard(_policy_permit(), cache=DefaultInMemoryCache(), cache_ttl=1)
    base = 1000.0

    def fake_monotonic():
        return fake_monotonic.t

    fake_monotonic.t = base
    # Patch monotonic used by DefaultInMemoryCache
    import rbacx.core.cache as cache_mod

    monkeypatch.setattr(cache_mod.time, "monotonic", fake_monotonic, raising=True)

    # first call -> miss, set
    g.evaluate_sync(Subject("u", []), Action("read"), Resource("doc", "1"), Context({}))
    assert g.decide_calls == 1

    # second call before expiry -> hit
    g.evaluate_sync(Subject("u", []), Action("read"), Resource("doc", "1"), Context({}))
    assert g.decide_calls == 1

    # advance time -> expiry -> miss -> second set
    fake_monotonic.t = base + 1.1
    g.evaluate_sync(Subject("u", []), Action("read"), Resource("doc", "1"), Context({}))
    assert g.decide_calls == 2


def test_set_policy_clears_cache():
    fc = FakeCache()
    g = SpyDeciderGuard(_policy_permit(), cache=fc)
    assert fc.clear_calls == 0
    # set a new policy (even same content) should clear cache via API
    g.set_policy(_policy_permit())
    assert fc.clear_calls == 1


def test_obligations_applied_on_each_evaluation():
    class FlippingObl:
        def __init__(self):
            self.calls = 0

        def check(self, raw, ctx):
            # flips between allowed True/False
            self.calls += 1
            ok = (self.calls % 2) == 1
            challenge = "step-up" if not ok else None
            return ok, challenge

    g = SpyDeciderGuard(
        _policy_permit(), cache=DefaultInMemoryCache(), obligation_checker=FlippingObl()
    )
    d1 = g.evaluate_sync(Subject("u", []), Action("read"), Resource("doc", "1"), Context({}))
    d2 = g.evaluate_sync(Subject("u", []), Action("read"), Resource("doc", "1"), Context({}))
    assert d1.allowed is True and d2.allowed is False
    assert d2.challenge == "step-up"


def test_cache_get_errors_are_swallowed(monkeypatch):
    class BoomCache(FakeCache):
        def get(self, key: str):
            raise RuntimeError("boom-get")

    g = SpyDeciderGuard(_policy_permit(), cache=BoomCache())
    d = g.evaluate_sync(Subject("u", []), Action("read"), Resource("doc", "1"), Context({}))
    assert d.allowed is True
    assert g.decide_calls == 1  # computed


def test_cache_set_errors_are_swallowed(monkeypatch):
    class BoomCache(FakeCache):
        def set(self, key: str, value, ttl=None):
            raise RuntimeError("boom-set")

    g = SpyDeciderGuard(_policy_permit(), cache=BoomCache())
    d = g.evaluate_sync(Subject("u", []), Action("read"), Resource("doc", "1"), Context({}))
    assert d.allowed is True
    assert g.decide_calls == 1  # computed, but set failed and was swallowed


def test_parallel_evaluations_do_not_crash():
    g = SpyDeciderGuard(_policy_permit(), cache=DefaultInMemoryCache())

    def worker():
        d = g.evaluate_sync(Subject("u", []), Action("read"), Resource("doc", "1"), Context({}))
        assert d.effect in ("permit", "deny")

    with ThreadPoolExecutor(max_workers=8) as ex:
        for _ in range(50):
            ex.submit(worker)


def test_policy_etag_absent_disables_caching(monkeypatch):
    fc = FakeCache()
    g = SpyDeciderGuard(_policy_permit(), cache=fc)
    # Forcefully remove etag to disable caching
    g.policy_etag = None
    g.evaluate_sync(Subject("u", []), Action("read"), Resource("doc", "1"), Context({}))
    # get/set should not be called because key is None
    assert fc.get_calls == 0
    assert fc.set_calls == 0


def test_env_with_non_json_types_is_stringified():
    class Weird:
        def __str__(self):
            return "<weird>"

    g = SpyDeciderGuard(_policy_permit(), cache=DefaultInMemoryCache())
    # Place non-JSON-serializable in context attrs
    ctx = Context(attrs={"obj": Weird()})
    d = g.evaluate_sync(Subject("u", []), Action("read"), Resource("doc", "1"), ctx)
    assert isinstance(d.allowed, bool)


def test_clear_cache_public_api():
    fc = FakeCache()
    g = SpyDeciderGuard(_policy_permit(), cache=fc)
    g.clear_cache()
    assert fc.clear_calls == 1


def test_cached_value_does_not_contain_sensitive_env():
    """
    Ensure that the cached VALUE does not contain the env (which may have secrets).
    Only the raw decision is cached.
    """
    fc = FakeCache()
    g = SpyDeciderGuard(_policy_permit(), cache=fc)
    # Perform evaluation to populate cache
    g.evaluate_sync(
        Subject("u", []), Action("read"), Resource("doc", "1"), Context({"password": "s"})
    )
    # Inspect stored values
    for v in fc.store.values():
        j = json.dumps(v)  # must be JSON encodable
        assert "password" not in j
