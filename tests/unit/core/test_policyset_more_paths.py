import importlib
import os

import rbacx.core.policyset as ps
from rbacx.core.policyset import decide


def _env():
    return {
        "action": "read",
        "resource": {"type": "doc", "id": "1", "attrs": {}},
        "subject": {"id": "u", "roles": [], "attrs": {}},
        "context": {},
    }


def test_policyset_all_unapplicable_even_nested():
    ps = {
        "policies": [
            {"id": "p-empty", "rules": []},
            {"id": "nested", "policies": [{"id": "inner-empty", "rules": []}]},
        ]
    }
    out = decide(ps, _env())
    assert out["decision"] == "deny" and out["reason"] == "no_match"


def test_conflicting_policies_deny_wins_and_ids_present():
    ps = {
        "policies": [
            {
                "id": "allowP",
                "rules": [
                    {
                        "id": "r-allow",
                        "actions": ["read"],
                        "resource": {"type": "doc"},
                        "effect": "permit",
                    }
                ],
            },
            {
                "id": "denyP",
                "rules": [
                    {
                        "id": "r-deny",
                        "actions": ["read"],
                        "resource": {"type": "doc"},
                        "effect": "deny",
                    }
                ],
            },
        ]
    }
    out = decide(ps, _env())
    assert out["decision"] == "deny"
    # last ids should refer to the matching deny rule where applicable
    assert out.get("last_rule_id") in ("r-deny", None)


CANDIDATES = [
    os.getenv("RBACX_DECIDE_MODULE"),
    "rbacx.policy.decider",
    "rbacx.policyset",  # fallback guesses
    "rbacx.core.policyset",
    "rbacx.engine.policyset",
]

mod = None
for name in filter(None, CANDIDATES):
    try:
        mod = importlib.import_module(name)
        break
    except ModuleNotFoundError:
        continue
if mod is None:
    raise ImportError(
        "Unable to import the module that contains `decide`. "
        "Set RBACX_DECIDE_MODULE to the correct module path."
    )


# --- 26: policies is NOT a list -> immediate 'no_match' deny result ---
def test_decide_policies_not_a_list_returns_no_match():
    # No need to patch evaluate_policy, the function returns early.
    out = mod.decide({"algorithm": "deny-overrides", "policies": {"id": "p1"}}, env={})
    assert out == {
        "decision": "deny",
        "reason": "no_match",
        "rule_id": None,
        "last_rule_id": None,
        "policy_id": None,
        "obligations": [],
    }


# --- 61–64: first deny under 'deny-overrides' sets deny_result/deny_pid and breaks ---
def test_decide_first_deny_triggers_deny_overrides_and_break(monkeypatch):
    # Patch evaluate_policy in the SAME module where `decide` is defined.
    def fake_eval(policy, env):
        pid = policy.get("id")
        if pid == "p1":
            # Applicable deny with a concrete rule id -> should set deny_result & break.
            return {"decision": "deny", "rule_id": "r1", "obligations": ["o1"]}
        # Would be skipped because we break after first deny.
        return {"decision": "permit", "rule_id": "r2", "obligations": ["o2"]}

    monkeypatch.setattr(mod, "evaluate_policy", fake_eval, raising=True)

    out = mod.decide(
        {
            "algorithm": "deny-overrides",
            "policies": [
                {"id": "p1"},  # triggers deny branch and break (lines 61–64)
                {"id": "p2"},
            ],
        },
        env={},
    )

    # Expect explicit deny shortcut with fields copied from first deny.
    assert out["decision"] == "deny"
    assert out["reason"] == "explicit_deny"
    assert out["rule_id"] == "r1"
    assert out["last_rule_id"] == "r1"
    assert out["policy_id"] == "p1"
    assert out["obligations"] == ["o1"]


# --- 74 and 116: decision is neither 'deny' nor 'permit' -> 'else: continue' then final no_match ---
def test_decide_else_continue_then_final_no_match_with_last_rule_id(monkeypatch):
    # Force applicable results (with rule_id) but decisions that are not deny/permit.
    def fake_eval(policy, env):
        # Applicable because a concrete rule id is present.
        return {"decision": "indeterminate", "rule_id": "rx"}

    monkeypatch.setattr(mod, "evaluate_policy", fake_eval, raising=True)

    out = mod.decide(
        {
            "algorithm": "permit-overrides",  # ensure we reach the very last return
            "policies": [
                {"id": "p1"},  # hits the `else: continue` path (line 74)
            ],
        },
        env={},
    )

    # We should hit the final "no_match" return (line 116), but with last_rule_id preserved.
    assert out == {
        "decision": "deny",
        "reason": "no_match",
        "rule_id": None,
        "last_rule_id": "rx",
        "policy_id": None,
        "obligations": [],
    }


def test_deny_overrides_breaks_on_first_deny(monkeypatch):
    # First deny should set deny_result/deny_pid and BREAK immediately
    seen = []

    def fake_evaluate(policy, env):
        pid = policy.get("id")
        seen.append(pid)
        if pid == "p1":
            # Applicable deny (must have a concrete rule id)
            return {"decision": "deny", "rule_id": "r1", "obligations": ["o1"]}
        # Would not be reached because we break on deny-overrides
        return {"decision": "permit", "rule_id": "rp"}

    monkeypatch.setattr(ps, "evaluate_policy", fake_evaluate, raising=True)

    out = ps.decide(
        {
            "algorithm": "deny-overrides",
            "policies": [
                {"id": "p1"},  # triggers deny -> sets deny_result -> algo==deny-overrides -> break
                {"id": "p2"},  # must not be evaluated
            ],
        },
        env={},
    )

    # We should have evaluated only the first policy
    assert seen == ["p1"]
    # And returned the explicit deny shortcut
    assert out == {
        "decision": "deny",
        "reason": "explicit_deny",
        "rule_id": "r1",
        "last_rule_id": "r1",
        "policy_id": "p1",
        "obligations": ["o1"],
    }


def test_permit_overrides_two_denies_then_permit_no_break(monkeypatch):
    # Cover the False branch of `if deny_result is None` (second deny) and
    # the False branch of `if algo == "deny-overrides"` (no break).
    seen = []

    def fake_evaluate(policy, env):
        pid = policy.get("id")
        seen.append(pid)
        if pid == "p1":
            return {"decision": "deny", "rule_id": "r1", "obligations": ["o1"]}
        if pid == "p2":
            # Second deny: deny_result is already set -> exercise the False branch
            return {"decision": "deny", "rule_id": "r2", "obligations": ["o2"]}
        if pid == "p3":
            return {"decision": "permit", "rule_id": "rp", "obligations": ["op"]}
        # Non-applicable fallback (should not be used)
        return {"decision": "deny", "rule_id": ""}

    monkeypatch.setattr(ps, "evaluate_policy", fake_evaluate, raising=True)

    out = ps.decide(
        {
            "algorithm": "permit-overrides",  # critical: do NOT break on deny
            "policies": [
                {"id": "p1"},  # first deny -> sets deny_result/deny_pid
                {"id": "p2"},  # second deny -> deny_result is not None
                {"id": "p3"},  # permit -> should win under permit-overrides
            ],
        },
        env={},
    )

    # All three evaluated (no break after first deny)
    assert seen == ["p1", "p2", "p3"]
    # Final result is permit and comes from p3
    assert out["decision"] == "permit"
    assert out["policy_id"] == "p3"
    assert out.get("rule_id") == "rp" or out.get("last_rule_id") == "rp"
    assert out.get("obligations") == ["op"]
