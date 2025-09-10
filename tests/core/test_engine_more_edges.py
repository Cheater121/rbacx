
from rbacx.core.engine import Guard

def test_recompute_etag_handles_bad_policy_and_compiler_none(monkeypatch):
    g = Guard(policy={"a": object()})  # not JSON-serializable -> except branch -> etag None
    assert getattr(g, "policy_etag", None) is None
    # Simulate failing compiler
    import rbacx.core.engine as eng
    monkeypatch.setattr(eng, "compile_policy", None, raising=False)
    g.set_policy({"ok": True})  # recompute uses compile_policy is None -> skip safely
    # Now force compiler exception path
    class _Boom:
        def __call__(self, p): raise RuntimeError("bad")
    monkeypatch.setattr(eng, "compile_policy", _Boom(), raising=False)
    g.set_policy({"ok": True})  # should not raise, _compiled becomes None
    assert getattr(g, "_compiled", None) is None
