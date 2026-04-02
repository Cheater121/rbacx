"""Tests for rbacx.ai._result dataclasses."""

import pytest

from rbacx.ai._result import DecisionExplanation, PolicyResult
from rbacx.core.decision import Decision


class TestPolicyResult:
    def test_minimal_construction(self, valid_policy_dict) -> None:
        result = PolicyResult(dsl=valid_policy_dict)
        assert result.dsl is valid_policy_dict
        assert result.warnings == []
        assert result.compiled is None
        assert result.explanation is None
        assert result.raw is None

    def test_full_construction(self, valid_policy_dict) -> None:
        result = PolicyResult(
            dsl=valid_policy_dict,
            warnings=[{"code": "W001", "message": "test"}],
            compiled=object(),
            explanation={"task_read": "Allows reading tasks"},
            raw='{"algorithm": "deny-overrides", "rules": [...]}',
        )
        assert len(result.warnings) == 1
        assert result.compiled is not None
        assert result.explanation == {"task_read": "Allows reading tasks"}
        assert result.raw is not None

    def test_is_frozen(self, valid_policy_dict) -> None:
        result = PolicyResult(dsl=valid_policy_dict)
        with pytest.raises(AttributeError):
            result.dsl = {}  # type: ignore[misc]

    def test_warnings_defaults_to_empty_list(self, valid_policy_dict) -> None:
        result = PolicyResult(dsl=valid_policy_dict)
        assert isinstance(result.warnings, list)
        assert len(result.warnings) == 0

    def test_two_instances_with_same_data_are_equal(self, valid_policy_dict) -> None:
        r1 = PolicyResult(dsl=valid_policy_dict, raw="x")
        r2 = PolicyResult(dsl=valid_policy_dict, raw="x")
        assert r1 == r2

    def test_none_fields_explicit(self, valid_policy_dict) -> None:
        result = PolicyResult(
            dsl=valid_policy_dict,
            compiled=None,
            explanation=None,
            raw=None,
        )
        assert result.compiled is None
        assert result.explanation is None
        assert result.raw is None


class TestDecisionExplanation:
    def _make_decision(self, allowed: bool = True) -> Decision:
        return Decision(
            allowed=allowed,
            effect="permit" if allowed else "deny",
            rule_id="task_read",
            reason="matched",
        )

    def test_construction(self) -> None:
        decision = self._make_decision(allowed=True)
        expl = DecisionExplanation(
            decision=decision,
            human="Access is allowed because the user has the reader role.",
        )
        assert expl.decision is decision
        assert "allowed" in expl.human.lower() or expl.human  # non-empty

    def test_is_frozen(self) -> None:
        decision = self._make_decision()
        expl = DecisionExplanation(decision=decision, human="text")
        with pytest.raises(AttributeError):
            expl.human = "other"  # type: ignore[misc]

    def test_denied_decision(self) -> None:
        decision = self._make_decision(allowed=False)
        expl = DecisionExplanation(decision=decision, human="Denied because no rule matched.")
        assert expl.decision.allowed is False

    def test_human_field_is_string(self) -> None:
        decision = self._make_decision()
        expl = DecisionExplanation(decision=decision, human="some explanation")
        assert isinstance(expl.human, str)

    def test_decision_field_is_decision_instance(self) -> None:
        decision = self._make_decision()
        expl = DecisionExplanation(decision=decision, human="text")
        assert isinstance(expl.decision, Decision)
