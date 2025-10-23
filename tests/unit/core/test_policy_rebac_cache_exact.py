import rbacx.core.policy as policy
from rbacx.core.relctx import REL_CHECKER, REL_LOCAL_CACHE


class AlwaysTrueChecker:
    """Checker that returns plain True (non-awaitable) to stay on the 'normal' path."""

    def __init__(self):
        self.calls = 0

    def check(self, subject, relation, resource, *, context=None):
        self.calls += 1
        return True


def test_rel_branch_return_when_cache_is_not_dict():
    """
    Force `isinstance(cache, dict)` to be False so the code executes:
        if isinstance(cache, dict):  # False -> skip write
            ...
        return allowed_bool           # line 273
    and we return the computed allowed_bool without touching cache.
    """
    checker = AlwaysTrueChecker()
    tok_checker = REL_CHECKER.set(checker)

    # <-- ключевой трюк: кэш НЕ dict, чтобы условие было False
    tok_cache = REL_LOCAL_CACHE.set(object())

    try:
        env = {
            "resource": {"type": "doc", "id": "A1"},
            "subject": {"id": "U1"},
            "context": {"_rebac": {"m": 1}},
        }
        cond = {"rel": "viewer"}

        out = policy.eval_condition(cond, env)
        assert out is True  # пришли на 'return allowed_bool'
        assert checker.calls == 1  # чекер действительно вызвали
        # (ничего проверить по кэшу нельзя: это не dict — и это именно то, чего добивались)
    finally:
        REL_LOCAL_CACHE.reset(tok_cache)
        REL_CHECKER.reset(tok_checker)
