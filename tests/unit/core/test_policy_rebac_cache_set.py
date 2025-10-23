import rbacx.core.policy as policy
from rbacx.core.relctx import REL_CHECKER, REL_LOCAL_CACHE


class TrueChecker:
    """Minimal checker that always allows; non-awaitable result to keep the path simple."""

    def __init__(self):
        self.calls = 0

    def check(self, subject, relation, resource, *, context=None):
        self.calls += 1
        return True


def test_rebac_cache_is_written_and_value_returned():
    """
    Covers lines 271–273 in rbacx/core/policy.py (rel branch):
      - cache[key] = allowed_bool
      - return allowed_bool
    Also asserts that the second call hits the cache (checker not called again).
    """
    checker = TrueChecker()
    tok_checker = REL_CHECKER.set(checker)  # set() -> later reset() via token (ContextVar pattern)
    cache: dict = {}
    tok_cache = REL_LOCAL_CACHE.set(cache)

    try:
        env = {
            "resource": {"type": "doc", "id": "X"},
            "subject": {"id": "U"},
            "context": {"_rebac": {"k": "v"}},
        }
        cond = {"rel": "viewer"}

        # First call: executes try-path, writes to cache, returns True.
        out1 = policy.eval_condition(cond, env)
        assert out1 is True
        assert len(cache) == 1

        # Second call: cache-hit → checker not called again, value returned from cache.
        out2 = policy.eval_condition(cond, env)
        assert out2 is True
        assert checker.calls == 1
    finally:
        # Properly restore ContextVars (set/reset pattern).
        REL_LOCAL_CACHE.reset(tok_cache)
        REL_CHECKER.reset(tok_checker)
