# tests/unit/adapters/test_fastapi_branches.py
import types

import pytest

import rbacx.adapters.fastapi as fa_mod


class DummyHTTPException(Exception):
    def __init__(self, status_code: int, detail=None, headers=None):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail
        self.headers = headers or {}


def _build_env(_req):
    # Minimal stand-ins; the dependency only passes them to guard methods.
    Subject = types.SimpleNamespace
    Action = types.SimpleNamespace
    Resource = types.SimpleNamespace
    Context = types.SimpleNamespace
    return (
        Subject(id="u"),
        Action(name="read"),
        Resource(type="doc", id="1", attrs={}),
        Context(attrs={}),
    )


def test_is_allowed_branch_returns_none(monkeypatch):
    """
    Cover lines 25–26: `elif hasattr(guard, "is_allowed")` and the call itself.
    Guard exposes *only* is_allowed and returns True → dependency returns None.
    """
    monkeypatch.setattr(fa_mod, "HTTPException", DummyHTTPException, raising=True)

    class GuardOK:
        def is_allowed(self, sub, act, res, ctx):
            return True

    dep = fa_mod.require_access(GuardOK(), _build_env, add_headers=False)
    assert dep(object()) is None  # allowed path, early return


def test_reason_false_rule_id_true_sets_rule_header(monkeypatch):
    """
    Cover arc 46->48 inside the `if expl is not None:` block:
      - `reason` is falsy → skip the 'reason' header (line 46)
      - `rule_id` is truthy → set 'X-RBACX-Rule' (line 48)
    """
    monkeypatch.setattr(fa_mod, "HTTPException", DummyHTTPException, raising=True)

    class Expl:
        reason = None
        rule_id = "rule-42"
        policy_id = None

    class GuardDenied:
        # No is_allowed_sync → falls into lines 25–26 branch but returns False
        def is_allowed(self, sub, act, res, ctx):
            return False

        # Prefer explain_sync to hit that path deterministically
        def explain_sync(self, sub, act, res, ctx):
            return Expl()

    dep = fa_mod.require_access(GuardDenied(), _build_env, add_headers=True)

    with pytest.raises(DummyHTTPException) as ei:
        dep(object())

    exc = ei.value
    assert exc.status_code == 403
    # reason header should be absent (reason is falsy)
    assert "X-RBACX-Reason" not in exc.headers
    # rule header should be present (rule_id is truthy)
    assert exc.headers.get("X-RBACX-Rule") == "rule-42"
