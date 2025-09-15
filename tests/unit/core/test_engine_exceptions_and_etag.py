from rbacx.core.engine import Guard
from rbacx.core.model import Action, Context, Resource, Subject


def _policy_permit():
    return {
        "rules": [{"id": "r", "actions": ["read"], "resource": {"type": "doc"}, "effect": "permit"}]
    }


class BoomObligations:
    def check(self, raw, context):
        raise RuntimeError("boom")


def test_obligations_exception_is_swallowed_and_allows():
    g = Guard(_policy_permit(), obligation_checker=BoomObligations())
    d = g.evaluate_sync(Subject("u", []), Action("read"), Resource("doc", "1"), Context({}))
    assert d.allowed is True


def test_recompute_etag_handles_non_serializable_policy_and_compile_error(monkeypatch):
    bad_policy = {
        "rules": [
            {"id": "r", "actions": ["read"], "resource": {"type": "doc"}, "effect": "permit"}
        ],
        "fn": lambda x: x,
    }
    g = Guard(bad_policy)
    import rbacx.core.engine as eng

    monkeypatch.setattr(
        eng,
        "compile_policy",
        lambda p: (_ for _ in ()).throw(RuntimeError("compile fail")),
        raising=True,
    )
    g.set_policy(bad_policy)
    d = g.evaluate_sync(Subject("u", []), Action("read"), Resource("doc", "1"), Context({}))
    assert d.allowed is True
