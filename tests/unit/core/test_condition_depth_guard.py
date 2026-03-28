"""Tests for the condition-depth DoS guard introduced in v1.9.3.

Security context
----------------
``eval_condition`` is recursive: ``and``/``or``/``not`` operators each make a
recursive call.  Before this fix a policy containing deeply nested conditions
(e.g. 500 ``and``-levels) caused a ``RecursionError`` that propagated out of
``evaluate()`` uncaught, crashing the interpreter thread.  An attacker who can
influence the policy loaded from an external source (HTTP, S3) could exploit
this for a denial-of-service.

The fix adds ``MAX_CONDITION_DEPTH = 50`` and a ``ConditionDepthError``
exception class.  ``eval_condition`` raises ``ConditionDepthError`` as soon as
``_depth`` exceeds the limit.  ``evaluate()`` catches it separately, logs a
warning, and treats the rule as a non-match (fail-closed).
"""

import pytest

from rbacx.core.policy import (
    MAX_CONDITION_DEPTH,
    ConditionDepthError,
    ConditionTypeError,
    eval_condition,
    evaluate,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _nested_and(depth: int) -> dict:
    """Build ``{"and": [{"and": [...]}]}`` with *depth* nesting levels."""
    cond: dict = {"==": [1, 1]}
    for _ in range(depth):
        cond = {"and": [cond]}
    return cond


def _nested_or(depth: int) -> dict:
    cond: dict = {"==": [1, 1]}
    for _ in range(depth):
        cond = {"or": [cond]}
    return cond


def _nested_not(depth: int) -> dict:
    cond: dict = {"==": [1, 0]}  # False at the bottom
    for _ in range(depth):
        cond = {"not": cond}
    return cond


def _base_env() -> dict:
    return {
        "action": "read",
        "resource": {"type": "doc", "id": "1", "attrs": {}},
        "subject": {"id": "u", "roles": [], "attrs": {}},
        "context": {},
    }


# ---------------------------------------------------------------------------
# MAX_CONDITION_DEPTH constant
# ---------------------------------------------------------------------------


def test_max_condition_depth_is_positive_int() -> None:
    """MAX_CONDITION_DEPTH must be a positive integer."""
    assert isinstance(MAX_CONDITION_DEPTH, int)
    assert MAX_CONDITION_DEPTH > 0


def test_max_condition_depth_default_value() -> None:
    """Default limit is 50 — generous for real policies, safe from crash threshold."""
    assert MAX_CONDITION_DEPTH == 50


# ---------------------------------------------------------------------------
# ConditionDepthError is a distinct exception
# ---------------------------------------------------------------------------


def test_condition_depth_error_is_exception_subclass() -> None:
    assert issubclass(ConditionDepthError, Exception)


def test_condition_depth_error_is_not_condition_type_error() -> None:
    """ConditionDepthError and ConditionTypeError must be independent."""
    assert not issubclass(ConditionDepthError, ConditionTypeError)
    assert not issubclass(ConditionTypeError, ConditionDepthError)


# ---------------------------------------------------------------------------
# eval_condition: depth guard fires at the right level
# ---------------------------------------------------------------------------


class TestEvalConditionDepthGuard:
    """eval_condition must raise ConditionDepthError above MAX_CONDITION_DEPTH."""

    def test_exactly_at_limit_does_not_raise(self) -> None:
        """A condition tree exactly MAX_CONDITION_DEPTH levels deep must be accepted."""
        cond = _nested_and(MAX_CONDITION_DEPTH)
        # Must not raise — returns True because 1 == 1 at the bottom
        result = eval_condition(cond, {})
        assert result is True

    def test_one_above_limit_raises_depth_error(self) -> None:
        """One level beyond MAX_CONDITION_DEPTH must raise ConditionDepthError."""
        cond = _nested_and(MAX_CONDITION_DEPTH + 1)
        with pytest.raises(ConditionDepthError):
            eval_condition(cond, {})

    def test_far_above_limit_raises_depth_error_not_recursion_error(self) -> None:
        """Deep nesting (500+) must raise ConditionDepthError, never RecursionError.

        This is the core DoS regression: before the fix, depth >= ~499 caused
        RecursionError which crashed the interpreter thread.
        """
        cond = _nested_and(500)
        with pytest.raises(ConditionDepthError):
            eval_condition(cond, {})

    def test_or_chain_raises_depth_error(self) -> None:
        """The depth guard applies to ``or`` chains, not only ``and``."""
        cond = _nested_or(MAX_CONDITION_DEPTH + 1)
        with pytest.raises(ConditionDepthError):
            eval_condition(cond, {})

    def test_not_chain_raises_depth_error(self) -> None:
        """The depth guard applies to ``not`` chains."""
        cond = _nested_not(MAX_CONDITION_DEPTH + 1)
        with pytest.raises(ConditionDepthError):
            eval_condition(cond, {})

    def test_mixed_nesting_raises_depth_error(self) -> None:
        """A mix of and/or/not contributes to the same depth counter."""
        # Build: and -> or -> not -> and -> or -> ... until limit exceeded
        cond: dict = {"==": [1, 1]}
        ops = ["and", "or", "not", "and", "or", "not"]
        for i in range(MAX_CONDITION_DEPTH + 2):
            op = ops[i % len(ops)]
            if op == "not":
                cond = {"not": cond}
            else:
                cond = {op: [cond]}
        with pytest.raises(ConditionDepthError):
            eval_condition(cond, {})

    def test_error_message_mentions_limit(self) -> None:
        """ConditionDepthError message must include the numeric limit."""
        cond = _nested_and(MAX_CONDITION_DEPTH + 1)
        with pytest.raises(ConditionDepthError, match=str(MAX_CONDITION_DEPTH)):
            eval_condition(cond, {})


# ---------------------------------------------------------------------------
# Legitimate conditions are unaffected
# ---------------------------------------------------------------------------


class TestLegitimateConditionsUnaffected:
    """Real-world condition trees must continue to work correctly."""

    def test_flat_and(self) -> None:
        cond = {"and": [{"==": [1, 1]}, {"==": [2, 2]}, {"==": [3, 3]}]}
        assert eval_condition(cond, {}) is True

    def test_flat_or(self) -> None:
        cond = {"or": [{"==": [1, 2]}, {"==": [2, 2]}]}
        assert eval_condition(cond, {}) is True

    def test_nested_3_deep(self) -> None:
        cond = {"and": [{"or": [{"not": {"==": [1, 2]}}]}]}
        assert eval_condition(cond, {}) is True

    def test_realistic_role_and_attr_check(self) -> None:
        env = {"subject": {"id": "alice", "roles": ["editor"], "attrs": {}}}
        cond = {
            "and": [
                {"hasAny": [{"attr": "subject.roles"}, ["admin", "editor"]]},
                {"not": {"==": [{"attr": "subject.id"}, "blocked"]}},
            ]
        }
        assert eval_condition(cond, env) is True

    def test_depth_exactly_at_limit_returns_correct_value(self) -> None:
        """A condition exactly at MAX_CONDITION_DEPTH must evaluate correctly."""
        # Bottom: False (1 == 2)
        cond: dict = {"==": [1, 2]}
        for _ in range(MAX_CONDITION_DEPTH):
            cond = {"not": cond}
        # MAX_CONDITION_DEPTH inversions of False — result depends on parity
        expected = (MAX_CONDITION_DEPTH % 2) == 1  # odd -> True, even -> False
        assert eval_condition(cond, {}) is expected


# ---------------------------------------------------------------------------
# evaluate() integration: fail-closed when depth exceeded
# ---------------------------------------------------------------------------


class TestEvaluateFailsClosedOnDepthExceeded:
    """evaluate() must catch ConditionDepthError and treat the rule as non-matching."""

    def _policy_with_deep_condition(self, depth: int) -> dict:
        return {
            "algorithm": "deny-overrides",
            "rules": [
                {
                    "id": "deep_rule",
                    "effect": "permit",
                    "actions": ["read"],
                    "resource": {"type": "doc"},
                    "condition": _nested_and(depth),
                },
            ],
        }

    def test_deep_condition_does_not_crash(self) -> None:
        """evaluate() must not raise RecursionError or ConditionDepthError."""
        policy = self._policy_with_deep_condition(500)
        env = _base_env()
        # Must complete without any exception
        result = evaluate(policy, env)
        assert isinstance(result, dict)

    def test_deep_condition_fails_closed(self) -> None:
        """When a rule's condition exceeds depth, the rule is skipped (fail-closed).

        With only one rule (a deep-condition permit) and no fallback, the
        decision must be deny.
        """
        policy = self._policy_with_deep_condition(500)
        result = evaluate(policy, _base_env())
        assert result["decision"] == "deny"

    def test_deep_condition_reason_is_depth_exceeded(self) -> None:
        """The reason field must be ``condition_depth_exceeded`` for the skipped rule."""
        policy = self._policy_with_deep_condition(500)
        result = evaluate(policy, _base_env())
        assert result["reason"] == "condition_depth_exceeded"

    def test_good_rules_after_deep_rule_are_still_evaluated(self) -> None:
        """Rules after a depth-exceeded rule must still be evaluated normally."""
        policy = {
            "algorithm": "deny-overrides",
            "rules": [
                {
                    "id": "deep_rule",
                    "effect": "permit",
                    "actions": ["read"],
                    "resource": {"type": "doc"},
                    "condition": _nested_and(500),
                },
                {
                    "id": "explicit_deny",
                    "effect": "deny",
                    "actions": ["*"],
                    "resource": {},
                },
            ],
        }
        result = evaluate(policy, _base_env())
        # deep_rule skipped -> explicit_deny matches -> deny
        assert result["decision"] == "deny"
        assert result["rule_id"] == "explicit_deny"

    def test_permit_still_granted_when_later_rule_matches(self) -> None:
        """A permit rule after the deep-condition rule must still be able to grant."""
        policy = {
            "algorithm": "permit-overrides",
            "rules": [
                {
                    "id": "deep_rule",
                    "effect": "deny",
                    "actions": ["read"],
                    "resource": {"type": "doc"},
                    "condition": _nested_and(500),
                },
                {
                    "id": "simple_permit",
                    "effect": "permit",
                    "actions": ["read"],
                    "resource": {"type": "doc"},
                },
            ],
        }
        result = evaluate(policy, _base_env())
        assert result["decision"] == "permit"
        assert result["rule_id"] == "simple_permit"

    def test_normal_condition_in_same_policy_unaffected(self) -> None:
        """A normal condition in the same policy must evaluate correctly."""
        env = {**_base_env(), "context": {"mfa": True}}
        env["context"] = {"mfa": True}
        policy = {
            "algorithm": "deny-overrides",
            "rules": [
                {
                    "id": "deep_rule",
                    "effect": "permit",
                    "actions": ["read"],
                    "resource": {"type": "doc"},
                    "condition": _nested_and(500),
                },
                {
                    "id": "mfa_permit",
                    "effect": "permit",
                    "actions": ["read"],
                    "resource": {"type": "doc"},
                    "condition": {"==": [{"attr": "context.mfa"}, True]},
                },
            ],
        }
        result = evaluate(policy, env)
        assert result["decision"] == "permit"
        assert result["rule_id"] == "mfa_permit"
