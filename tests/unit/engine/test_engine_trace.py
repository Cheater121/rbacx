"""Unit tests for Decision.trace / explain=True across all evaluation paths."""

import pytest

from rbacx import Action, Context, Guard, Resource, Subject
from rbacx.core.decision import Decision, RuleTrace
from rbacx.core.policy import MAX_CONDITION_DEPTH

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_S = Subject(id="u1")
_R = Resource(type="doc", id="d1")
_CTX = Context()


def _policy(*rules, algo: str = "deny-overrides") -> dict:
    return {"algorithm": algo, "rules": list(rules)}


def _rule(rid, effect, actions, rtype="doc", condition=None):
    rule = {"id": rid, "effect": effect, "actions": actions, "resource": {"type": rtype}}
    if condition is not None:
        rule["condition"] = condition
    return rule


# ---------------------------------------------------------------------------
# explain=False (default) — backward compatibility
# ---------------------------------------------------------------------------


def test_trace_none_by_default():
    """explain=False must leave Decision.trace as None."""
    g = Guard(_policy(_rule("r1", "permit", ["read"])))
    d = g.evaluate_sync(_S, Action("read"), _R, _CTX)
    assert d.trace is None


def test_decision_trace_field_default_none():
    """Decision dataclass default: trace=None."""
    d = Decision(allowed=True, effect="permit")
    assert d.trace is None


# ---------------------------------------------------------------------------
# Basic trace content
# ---------------------------------------------------------------------------


def test_single_matched_rule_trace():
    """One matching rule → one RuleTrace entry, matched=True, skip_reason=None."""
    g = Guard(_policy(_rule("r1", "permit", ["read"])))
    d = g.evaluate_sync(_S, Action("read"), _R, _CTX, explain=True)

    assert d.trace is not None and len(d.trace) == 1
    t = d.trace[0]
    assert isinstance(t, RuleTrace)
    assert t.rule_id == "r1"
    assert t.effect == "permit"
    assert t.matched is True
    assert t.skip_reason is None


def test_ruletrace_field_types():
    """RuleTrace fields have expected Python types."""
    g = Guard(_policy(_rule("r1", "permit", ["read"])))
    d = g.evaluate_sync(_S, Action("read"), _R, _CTX, explain=True)
    t = d.trace[0]
    assert isinstance(t.rule_id, str)
    assert isinstance(t.effect, str) and t.effect in ("permit", "deny")
    assert isinstance(t.matched, bool)
    assert t.skip_reason is None or isinstance(t.skip_reason, str)


# ---------------------------------------------------------------------------
# Skip reasons
# ---------------------------------------------------------------------------


def test_action_mismatch_in_trace():
    """Rule whose actions list does not include the requested action is recorded
    with skip_reason='action_mismatch'."""
    g = Guard(_policy(_rule("r1", "permit", ["write"])))
    d = g.evaluate_sync(_S, Action("read"), _R, _CTX, explain=True)

    assert d.trace and len(d.trace) == 1
    assert d.trace[0].skip_reason == "action_mismatch"
    assert d.trace[0].matched is False


def test_resource_mismatch_in_trace():
    """Rule whose resource type does not match is recorded with
    skip_reason='resource_mismatch'."""
    g = Guard(_policy(_rule("r1", "permit", ["read"], rtype="file")))
    d = g.evaluate_sync(_S, Action("read"), _R, _CTX, explain=True)

    assert d.trace and d.trace[0].skip_reason == "resource_mismatch"
    assert d.trace[0].matched is False


def test_condition_mismatch_in_trace():
    """Rule whose condition evaluates to False is recorded with
    skip_reason='condition_mismatch'."""
    cond = {"==": [{"attr": "subject.id"}, "admin"]}
    g = Guard(_policy(_rule("r1", "permit", ["read"], condition=cond)))
    d = g.evaluate_sync(_S, Action("read"), _R, _CTX, explain=True)

    assert d.trace and d.trace[0].skip_reason == "condition_mismatch"
    assert d.trace[0].matched is False


def test_condition_type_mismatch_in_trace():
    """Rule that raises ConditionTypeError is recorded with
    skip_reason='condition_type_mismatch'."""
    cond = {">": [{"attr": "subject.id"}, 42]}  # str > int → type error
    g = Guard(_policy(_rule("r1", "permit", ["read"], condition=cond)))
    d = g.evaluate_sync(_S, Action("read"), _R, _CTX, explain=True)

    assert d.trace and d.trace[0].skip_reason == "condition_type_mismatch"
    assert d.trace[0].matched is False


def test_condition_depth_exceeded_in_trace():
    """Rule that raises ConditionDepthError is recorded with
    skip_reason='condition_depth_exceeded'."""
    deep: dict = {"==": [1, 1]}
    for _ in range(MAX_CONDITION_DEPTH + 2):
        deep = {"and": [deep]}
    g = Guard(_policy(_rule("rdepth", "permit", ["read"], condition=deep)))
    d = g.evaluate_sync(_S, Action("read"), _R, _CTX, explain=True)

    assert d.trace and d.trace[0].skip_reason == "condition_depth_exceeded"
    assert d.trace[0].matched is False


# ---------------------------------------------------------------------------
# Algorithm-specific trace behaviour
# ---------------------------------------------------------------------------


def test_deny_overrides_trace_stops_after_deny_break():
    """deny-overrides: loop breaks immediately after the first matching deny.
    Rules declared after that deny are absent from the trace."""
    policy = _policy(
        _rule("skip-write", "permit", ["write"]),  # action mismatch for "read"
        _rule("permit-read", "permit", ["read"]),  # matched → recorded
        _rule("deny-all", "deny", ["read"]),  # matched → deny, break
        _rule("after-deny", "permit", ["read"]),  # never reached
    )
    g = Guard(policy)
    d = g.evaluate_sync(_S, Action("read"), _R, _CTX, explain=True)

    assert d.allowed is False
    ids = [t.rule_id for t in d.trace]
    assert "skip-write" in ids
    assert "permit-read" in ids
    assert "deny-all" in ids
    assert "after-deny" not in ids
    assert ids == ["skip-write", "permit-read", "deny-all"]


def test_deny_overrides_full_scan_all_permits():
    """deny-overrides: when no deny fires, loop runs to completion — all rules
    are present in the trace."""
    policy = _policy(
        _rule("p1", "permit", ["read"]),
        _rule("p2", "permit", ["read"]),
        _rule("p3", "permit", ["read"]),
    )
    g = Guard(policy)
    d = g.evaluate_sync(_S, Action("read"), _R, _CTX, explain=True)

    assert d.allowed is True
    assert [t.rule_id for t in d.trace] == ["p1", "p2", "p3"]


def test_permit_overrides_trace_stops_after_permit_break():
    """permit-overrides: loop breaks at the first matching permit.
    Rules declared after are absent from the trace."""
    policy = _policy(
        _rule("deny-all", "deny", ["read"]),  # matched → recorded
        _rule("permit-read", "permit", ["read"]),  # matched → permit, break
        _rule("after-permit", "deny", ["read"]),  # never reached
        algo="permit-overrides",
    )
    g = Guard(policy)
    d = g.evaluate_sync(_S, Action("read"), _R, _CTX, explain=True)

    assert d.allowed is True
    ids = [t.rule_id for t in d.trace]
    assert "deny-all" in ids
    assert "permit-read" in ids
    assert "after-permit" not in ids
    assert ids == ["deny-all", "permit-read"]


def test_first_applicable_stops_at_first_match():
    """first-applicable: trace contains only rules up to (and including) the
    first match; subsequent rules are absent."""
    policy = _policy(
        _rule("skip-action", "permit", ["write"]),  # action mismatch
        _rule("first-match", "permit", ["read"]),  # matched → break
        _rule("never-seen", "deny", ["read"]),  # never reached
        algo="first-applicable",
    )
    g = Guard(policy)
    d = g.evaluate_sync(_S, Action("read"), _R, _CTX, explain=True)

    assert d.allowed is True
    ids = [t.rule_id for t in d.trace]
    assert "skip-action" in ids
    assert "first-match" in ids
    assert "never-seen" not in ids


def test_no_match_all_rules_skipped_in_trace():
    """When no rule matches, every rule appears in the trace with matched=False."""
    g = Guard(_policy(_rule("r1", "permit", ["write"])))
    d = g.evaluate_sync(_S, Action("read"), _R, _CTX, explain=True)

    assert d.allowed is False
    assert len(d.trace) == 1
    assert d.trace[0].matched is False


# ---------------------------------------------------------------------------
# explain=True does not change allowed / effect
# ---------------------------------------------------------------------------


def test_explain_does_not_change_allowed_or_effect():
    """explain=True must not alter allowed or effect for any action."""
    policy = _policy(
        _rule("r-deny", "deny", ["delete"]),
        _rule("r-perm", "permit", ["read"]),
    )
    g = Guard(policy)
    for action_name in ("read", "delete"):
        dp = g.evaluate_sync(_S, Action(action_name), _R, _CTX)
        dt = g.evaluate_sync(_S, Action(action_name), _R, _CTX, explain=True)
        assert dp.allowed == dt.allowed, f"allowed differs for {action_name}"
        assert dp.effect == dt.effect, f"effect differs for {action_name}"


def test_explain_flag_not_leaked_between_calls():
    """A subsequent call without explain=True must not carry over __explain__
    from a previous call and must return trace=None."""
    g = Guard(_policy(_rule("r1", "permit", ["read"])))
    _ = g.evaluate_sync(_S, Action("read"), _R, _CTX, explain=True)
    d = g.evaluate_sync(_S, Action("read"), _R, _CTX)
    assert d.trace is None


# ---------------------------------------------------------------------------
# Async and batch APIs
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_evaluate_async_explain():
    """evaluate_async with explain=True populates trace."""
    g = Guard(_policy(_rule("r1", "permit", ["read"])))
    d = await g.evaluate_async(_S, Action("read"), _R, _CTX, explain=True)

    assert d.trace is not None
    assert d.trace[0].matched is True
    assert d.trace[0].rule_id == "r1"


@pytest.mark.asyncio
async def test_evaluate_batch_async_explain_per_request():
    """evaluate_batch_async with explain=True populates trace on each Decision."""
    g = Guard(_policy(_rule("r1", "permit", ["read"])))
    results = await g.evaluate_batch_async(
        [
            (_S, Action("read"), _R, _CTX),
            (_S, Action("write"), _R, _CTX),
        ],
        explain=True,
    )
    # first request: matched
    assert results[0].trace is not None
    assert results[0].trace[0].matched is True
    # second request: action mismatch
    assert results[1].trace is not None
    assert results[1].trace[0].skip_reason == "action_mismatch"


def test_evaluate_batch_sync_explain():
    """evaluate_batch_sync with explain=True populates trace on each Decision."""
    g = Guard(_policy(_rule("r1", "permit", ["read"])))
    results = g.evaluate_batch_sync(
        [(_S, Action("read"), _R, _CTX)],
        explain=True,
    )
    assert results[0].trace is not None
    assert results[0].trace[0].matched is True


@pytest.mark.asyncio
async def test_evaluate_batch_async_no_explain_trace_none():
    """evaluate_batch_async without explain=True → trace=None on every Decision."""
    g = Guard(_policy(_rule("r1", "permit", ["read"])))
    results = await g.evaluate_batch_async([(_S, Action("read"), _R, _CTX)])
    assert results[0].trace is None


# ---------------------------------------------------------------------------
# PolicySet trace
# ---------------------------------------------------------------------------


def test_policyset_trace_contains_child_rules():
    """Trace for a policy set contains rule entries from the child policy that
    produced the decision."""
    ps = {
        "algorithm": "deny-overrides",
        "policies": [
            {
                "id": "p1",
                "algorithm": "deny-overrides",
                "rules": [
                    {
                        "id": "ps-r1",
                        "effect": "permit",
                        "actions": ["read"],
                        "resource": {"type": "doc"},
                    }
                ],
            }
        ],
    }
    g = Guard(ps)
    d = g.evaluate_sync(_S, Action("read"), _R, _CTX, explain=True)

    assert d.allowed is True
    assert d.trace is not None
    assert any(t.rule_id == "ps-r1" for t in d.trace)


# ---------------------------------------------------------------------------
# Public API: RuleTrace importable from rbacx root
# ---------------------------------------------------------------------------


def test_ruletrace_importable_from_rbacx():
    """RuleTrace must be importable directly from the rbacx package."""
    from rbacx import RuleTrace as RT
    from rbacx.core.decision import RuleTrace as RTCore

    assert RT is RTCore
