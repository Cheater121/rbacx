import rbacx.core.policy as policy
from rbacx.core.relctx import EVAL_LOOP, REL_CHECKER, REL_LOCAL_CACHE

# ------------------------- _canon_subject / _canon_resource -------------------------


def test_canon_subject_variants():
    env = {"subject": {"id": "7"}}
    # override not provided -> takes from env
    assert policy._canon_subject(env) == "user:7"
    # override as plain id (without type) -> coerced to user:<id>
    assert policy._canon_subject(env, "42") == "user:42"
    # override as fully qualified -> returned as-is
    assert policy._canon_subject(env, "user:99") == "user:99"
    # override as {"attr": "..."} path resolved through env
    env2 = {"subject": {"id": "abc"}}
    assert policy._canon_subject(env2, {"attr": "subject.id"}) == "user:abc"
    # no subject in env -> fallback "user:"
    assert policy._canon_subject({}) == "user:"


def test_canon_resource_variants():
    env = {"resource": {"type": "doc", "id": "5"}}
    # override fully qualified -> returned as-is
    assert policy._canon_resource(env, "photo:777") == "photo:777"
    # override id only -> use current env type
    assert policy._canon_resource(env, "9") == "doc:9"
    # no override -> use env
    assert policy._canon_resource(env) == "doc:5"
    # no id in env -> keep type and trailing colon
    assert policy._canon_resource({"resource": {"type": "img"}}, None) == "img:"
    # no type in env -> default "object"
    assert policy._canon_resource({"resource": {"id": "3"}}, None) == "object:3"


# ------------------------------ _ctx_hash ------------------------------


def test_ctx_hash_json_and_fallback_repr():
    # JSON-able dict -> stable json with sorted keys
    got = policy._ctx_hash({"b": 2, "a": 1})
    assert got == '{"a":1,"b":2}'

    # Keys must be strings in JSON; using non-string key forces the except-branch (repr)
    class K:
        def __repr__(self):
            return "<K>"

    bad = {K(): 1}  # json.dumps raises TypeError: keys must be str, int, float, bool, or None
    got2 = policy._ctx_hash(bad)
    assert "<K>" in got2  # came from repr(ctx)


# ------------------------------ eval_condition: rel branch ------------------------------


class DummyChecker:
    def __init__(self, result=True):
        self.calls = []
        self.result = result

    def check(self, subj, rel, res, *, context=None):
        self.calls.append((subj, rel, res, context))
        return self.result


def test_rel_branch_without_checker_fail_closed():
    # REL_CHECKER not set -> fail-closed (False)
    token = REL_CHECKER.set(None)
    try:
        env = {"action": "", "resource": {"type": "doc", "id": "1"}}
        assert policy.eval_condition({"rel": "viewer"}, env) is False
    finally:
        REL_CHECKER.reset(token)


def test_rel_branch_string_expr_merges_env_and_local_ctx_and_caches(monkeypatch):
    # Install checker and an in-memory local cache
    ck = DummyChecker(result=True)
    t1 = REL_CHECKER.set(ck)
    t2 = REL_LOCAL_CACHE.set({})
    try:
        env = {
            "resource": {"type": "doc", "id": "10"},
            "subject": {"id": "42"},
            "context": {"_rebac": {"a": 1}},
        }
        cond = {"rel": "viewer"}  # simple string form
        out1 = policy.eval_condition(cond, env)
        assert out1 is True

        # A second call should hit the cache, so ck.calls length stays 1
        out2 = policy.eval_condition(cond, env)
        assert out2 is True
        assert len(ck.calls) == 1
    finally:
        REL_LOCAL_CACHE.reset(t2)
        REL_CHECKER.reset(t1)


def test_rel_branch_dict_expr_overrides_and_local_ctx_merge():
    ck = DummyChecker(result=True)
    t1 = REL_CHECKER.set(ck)
    t2 = REL_LOCAL_CACHE.set({})
    try:
        env = {
            "resource": {"type": "doc", "id": "77"},
            "subject": {"id": "u1"},
            "context": {"_rebac": {"from_env": True}},
        }
        cond = {
            "rel": {
                "relation": "editor",
                "subject": "user:u2",
                "resource": "img:99",
                "ctx": {"local": 123},
            }
        }
        assert policy.eval_condition(cond, env) is True

        # Ensure the checker saw merged context: env._rebac updated by local ctx
        (subj, rel, res, ctx) = ck.calls[-1]
        assert subj == "user:u2" and rel == "editor" and res == "img:99"
        assert ctx == {"from_env": True, "local": 123}
    finally:
        REL_LOCAL_CACHE.reset(t2)
        REL_CHECKER.reset(t1)


def test_rel_branch_empty_or_wrong_expr_forms():
    t1 = REL_CHECKER.set(DummyChecker(result=True))
    try:
        env = {"resource": {"type": "t", "id": "1"}, "subject": {"id": "s"}}
        assert policy.eval_condition({"rel": {"relation": ""}}, env) is False  # empty relation
        assert policy.eval_condition({"rel": 123}, env) is False  # unsupported type
    finally:
        REL_CHECKER.reset(t1)


def test_rel_branch_awaitable_resolved_via_injected_helper(monkeypatch):
    # Arrange a checker that returns an "awaitable-looking" value; policy will always
    # call resolve_awaitable_in_worker() when EVAL_LOOP is not None.
    class AwaitableLike:
        def __await__(self):
            # make Python treat this as awaitable (not actually awaited by policy)
            if False:
                yield  # pragma: no cover
            return (yield from (x for x in []))  # empty iterator

    ck = DummyChecker(result=AwaitableLike())
    t1 = REL_CHECKER.set(ck)
    t2 = REL_LOCAL_CACHE.set({})

    # Set a non-None loop marker to trigger the resolver branch
    t3 = EVAL_LOOP.set(object())

    called = {}

    def fake_resolver(value, loop, timeout):
        called["seen"] = (value, loop, timeout)
        return True  # pretend the awaitable resolved to True

    try:
        # Patch the directly-imported helper in policy
        monkeypatch.setattr(policy, "resolve_awaitable_in_worker", fake_resolver, raising=True)
        env = {"resource": {"type": "doc", "id": "5"}, "subject": {"id": "s"}}
        assert policy.eval_condition({"rel": "viewer"}, env) is True
        # Ensure our fake resolver was invoked
        assert "seen" in called and called["seen"][2] == 5.0
    finally:
        EVAL_LOOP.reset(t3)
        REL_LOCAL_CACHE.reset(t2)
        REL_CHECKER.reset(t1)
