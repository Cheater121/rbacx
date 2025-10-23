import rbacx.core.policy as policy
from rbacx.core.relctx import REL_CHECKER, REL_LOCAL_CACHE

# ---- 130->132: _canon_subject override branches, including non-string fallback ----


def test_canon_subject_override_colon_and_plain_and_nonstring():
    env = {"subject": {"id": "7"}}
    # ":" branch (returns as-is)
    assert policy._canon_subject(env, "user:abc") == "user:abc"
    # no ":" branch (prefix with user:)
    assert policy._canon_subject(env, "abc") == "user:abc"
    # non-string override -> fall back to env
    assert policy._canon_subject(env, {"attr": "subject"}) == "user:7"


# ---- 139->144: _canon_resource override branches, including non-string fallback ----


def test_canon_resource_override_fully_qualified_plain_and_nonstring():
    env = {"resource": {"type": "doc", "id": "5"}}
    # ":" branch (returns as-is)
    assert policy._canon_resource(env, "photo:1") == "photo:1"
    # no ":" branch (use env type)
    assert policy._canon_resource(env, "9") == "doc:9"
    # non-string override -> fall back to env
    assert policy._canon_resource(env, {"attr": "resource"}) == "doc:5"


# ---- 260-269 / 271->273: try/except path + cache update and return ----


class RaisingChecker:
    def __init__(self):
        self.calls = 0

    def check(self, subj, rel, res, *, context=None):
        self.calls += 1
        raise RuntimeError("boom")


def test_rel_branch_exception_logged_and_cached(monkeypatch):
    # Install failing checker and a dict cache
    ck = RaisingChecker()
    t1 = REL_CHECKER.set(ck)
    cache = {}
    t2 = REL_LOCAL_CACHE.set(cache)
    try:
        env = {"resource": {"type": "doc", "id": "1"}, "subject": {"id": "s"}}
        # First call hits try/except -> allowed_bool=False; cache should be written; value returned False
        assert policy.eval_condition({"rel": "viewer"}, env) is False
        assert len(cache) == 1
        # Second call should NOT increment checker.calls because of cache hit
        assert policy.eval_condition({"rel": "viewer"}, env) is False
        assert ck.calls == 1
    finally:
        REL_LOCAL_CACHE.reset(t2)
        REL_CHECKER.reset(t1)
