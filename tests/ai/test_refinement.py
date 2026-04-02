"""Tests for rbacx.ai._refinement.RefinementSession."""

import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from rbacx.ai._generator import PolicyGenerator
from rbacx.ai._refinement import RefinementIteration, RefinementSession
from rbacx.ai._result import PolicyResult
from rbacx.ai._validator import PolicyValidator
from rbacx.ai.exceptions import PolicyGenerationError, ValidationRetryError

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _policy(rule_id: str = "r1") -> dict[str, Any]:
    return {
        "algorithm": "deny-overrides",
        "rules": [
            {
                "id": rule_id,
                "effect": "permit",
                "actions": ["read"],
                "resource": {"type": "doc"},
            }
        ],
    }


def _raw(rule_id: str = "r1") -> str:
    return json.dumps(_policy(rule_id))


def _initial_messages() -> list[dict[str, str]]:
    return [
        {"role": "system", "content": "dsl spec"},
        {"role": "user", "content": "generate a policy for this schema"},
    ]


def _make_session(
    *llm_responses: str,
    initial_policy: dict[str, Any] | None = None,
) -> tuple[RefinementSession, MagicMock]:
    """Return (session, mock_llm_client)."""
    client = MagicMock()
    client.complete = AsyncMock(side_effect=list(llm_responses))

    generator = PolicyGenerator(client)
    validator = PolicyValidator()

    session = RefinementSession(
        client=client,
        generator=generator,
        validator=validator,
        initial_policy=initial_policy or _policy(),
        initial_messages=_initial_messages(),
    )
    return session, client


# ---------------------------------------------------------------------------
# Initial state
# ---------------------------------------------------------------------------


class TestRefinementSessionInit:
    def test_current_policy_equals_initial(self) -> None:
        initial = _policy("init_rule")
        session, _ = _make_session(initial_policy=initial)
        assert session.current_policy == initial

    def test_history_is_empty(self) -> None:
        session, _ = _make_session()
        assert session.history == []

    def test_history_returns_copy(self) -> None:
        session, _ = _make_session()
        h1 = session.history
        h2 = session.history
        assert h1 is not h2  # new list each time


# ---------------------------------------------------------------------------
# refine() — single call
# ---------------------------------------------------------------------------


class TestRefinementSessionRefine:
    @pytest.mark.asyncio
    async def test_returns_policy_result(self) -> None:
        session, _ = _make_session(_raw("r_new"))
        with patch("rbacx.ai._generator.PolicyValidator.validate", return_value=[]):
            result = await session.refine("deny delete for viewers")
        assert isinstance(result, PolicyResult)

    @pytest.mark.asyncio
    async def test_result_dsl_is_new_policy(self) -> None:
        new_policy = _policy("r_new")
        session, _ = _make_session(json.dumps(new_policy))
        with patch("rbacx.ai._generator.PolicyValidator.validate", return_value=[]):
            result = await session.refine("some feedback")
        assert result.dsl == new_policy

    @pytest.mark.asyncio
    async def test_current_policy_updated_after_refine(self) -> None:
        new_policy = _policy("r_new")
        session, _ = _make_session(json.dumps(new_policy))
        with patch("rbacx.ai._generator.PolicyValidator.validate", return_value=[]):
            await session.refine("feedback")
        assert session.current_policy == new_policy

    @pytest.mark.asyncio
    async def test_history_grows_by_one(self) -> None:
        session, _ = _make_session(_raw("r_new"))
        with patch("rbacx.ai._generator.PolicyValidator.validate", return_value=[]):
            await session.refine("feedback")
        assert len(session.history) == 1

    @pytest.mark.asyncio
    async def test_history_entry_feedback(self) -> None:
        session, _ = _make_session(_raw())
        with patch("rbacx.ai._generator.PolicyValidator.validate", return_value=[]):
            await session.refine("deny delete for viewers")
        assert session.history[0].feedback == "deny delete for viewers"

    @pytest.mark.asyncio
    async def test_history_entry_policy(self) -> None:
        new_policy = _policy("r_updated")
        session, _ = _make_session(json.dumps(new_policy))
        with patch("rbacx.ai._generator.PolicyValidator.validate", return_value=[]):
            await session.refine("feedback")
        assert session.history[0].policy == new_policy

    @pytest.mark.asyncio
    async def test_history_entry_timestamp_is_positive_float(self) -> None:
        session, _ = _make_session(_raw())
        with patch("rbacx.ai._generator.PolicyValidator.validate", return_value=[]):
            await session.refine("feedback")
        assert isinstance(session.history[0].timestamp, float)
        assert session.history[0].timestamp > 0

    @pytest.mark.asyncio
    async def test_result_raw_is_none(self) -> None:
        session, _ = _make_session(_raw())
        with patch("rbacx.ai._generator.PolicyValidator.validate", return_value=[]):
            result = await session.refine("feedback")
        assert result.raw is None

    @pytest.mark.asyncio
    async def test_result_explanation_is_none(self) -> None:
        session, _ = _make_session(_raw())
        with patch("rbacx.ai._generator.PolicyValidator.validate", return_value=[]):
            result = await session.refine("feedback")
        assert result.explanation is None

    @pytest.mark.asyncio
    async def test_warnings_from_lint_in_result(self) -> None:
        session, _ = _make_session(_raw())
        fake_issue = {"code": "W001", "message": "test warning"}
        with patch("rbacx.ai._generator.PolicyValidator.validate", return_value=[]):
            with patch.object(PolicyValidator, "lint", return_value=[fake_issue]):
                result = await session.refine("feedback")
        assert result.warnings == [fake_issue]


# ---------------------------------------------------------------------------
# refine() — conversation history propagation
# ---------------------------------------------------------------------------


class TestRefinementSessionHistory:
    @pytest.mark.asyncio
    async def test_second_refine_messages_longer_than_first(self) -> None:
        session, client = _make_session(_raw("r1"), _raw("r2"))
        with patch("rbacx.ai._generator.PolicyValidator.validate", return_value=[]):
            await session.refine("first feedback")
            len_after_first = len(client.complete.call_args_list[0][0][0])
            await session.refine("second feedback")
            len_after_second = len(client.complete.call_args_list[1][0][0])
        assert len_after_second > len_after_first

    @pytest.mark.asyncio
    async def test_second_refine_history_has_two_entries(self) -> None:
        session, _ = _make_session(_raw("r1"), _raw("r2"))
        with patch("rbacx.ai._generator.PolicyValidator.validate", return_value=[]):
            await session.refine("first feedback")
            await session.refine("second feedback")
        assert len(session.history) == 2

    @pytest.mark.asyncio
    async def test_history_order_oldest_first(self) -> None:
        session, _ = _make_session(_raw("r1"), _raw("r2"))
        with patch("rbacx.ai._generator.PolicyValidator.validate", return_value=[]):
            await session.refine("first")
            await session.refine("second")
        assert session.history[0].feedback == "first"
        assert session.history[1].feedback == "second"

    @pytest.mark.asyncio
    async def test_messages_contain_previous_policy_as_assistant(self) -> None:
        """After first refine, second LLM call must see first policy in messages."""
        initial = _policy("initial")
        first_refined = _policy("first_refined")
        second_refined = _policy("second_refined")

        session, client = _make_session(
            json.dumps(first_refined),
            json.dumps(second_refined),
            initial_policy=initial,
        )
        with patch("rbacx.ai._generator.PolicyValidator.validate", return_value=[]):
            await session.refine("first feedback")
            await session.refine("second feedback")

        second_call_msgs: list[dict[str, str]] = client.complete.call_args_list[1][0][0]
        all_content = " ".join(m["content"] for m in second_call_msgs)
        # The first refined policy's rule id must appear somewhere in the messages
        assert "first_refined" in all_content


# ---------------------------------------------------------------------------
# refine() — compile flag
# ---------------------------------------------------------------------------


class TestRefinementSessionCompile:
    @pytest.mark.asyncio
    async def test_compile_false_gives_none_compiled(self) -> None:
        session, _ = _make_session(_raw())
        with patch("rbacx.ai._generator.PolicyValidator.validate", return_value=[]):
            result = await session.refine("feedback", compile=False)
        assert result.compiled is None

    @pytest.mark.asyncio
    async def test_compile_true_calls_compiler(self) -> None:
        session, _ = _make_session(_raw())
        fake_compiled = object()
        with patch("rbacx.ai._generator.PolicyValidator.validate", return_value=[]):
            with patch(
                "rbacx.ai._refinement.RefinementSession._compile",
                return_value=fake_compiled,
            ) as mock_compile:
                result = await session.refine("feedback", compile=True)
        mock_compile.assert_called_once()
        assert result.compiled is fake_compiled

    @pytest.mark.asyncio
    async def test_compile_true_unavailable_raises(self) -> None:
        session, _ = _make_session(_raw())
        with patch("rbacx.ai._generator.PolicyValidator.validate", return_value=[]):
            with patch(
                "rbacx.ai._refinement.RefinementSession._compile",
                side_effect=PolicyGenerationError("compiler unavailable"),
            ):
                with pytest.raises(PolicyGenerationError, match="compiler"):
                    await session.refine("feedback", compile=True)


# ---------------------------------------------------------------------------
# refine() — validation failure does not mutate state
# ---------------------------------------------------------------------------


class TestRefinementSessionStateOnFailure:
    @pytest.mark.asyncio
    async def test_state_not_updated_on_validation_retry_error(self) -> None:
        initial = _policy("original")
        session, _ = _make_session(
            # Two invalid responses → ValidationRetryError
            json.dumps({"algorithm": "deny-overrides"}),
            json.dumps({"algorithm": "deny-overrides"}),
            initial_policy=initial,
        )
        with patch(
            "rbacx.ai._generator.PolicyValidator.validate",
            return_value=["rules is required"],
        ):
            with pytest.raises(ValidationRetryError):
                await session.refine("feedback that causes failure")

        # State must be unchanged
        assert session.current_policy == initial
        assert session.history == []

    @pytest.mark.asyncio
    async def test_state_not_updated_on_json_parse_error(self) -> None:
        initial = _policy("original")
        session, _ = _make_session("not json at all", initial_policy=initial)
        with patch("rbacx.ai._generator.PolicyValidator.validate", return_value=[]):
            with pytest.raises(PolicyGenerationError):
                await session.refine("feedback")
        assert session.current_policy == initial
        assert session.history == []


# ---------------------------------------------------------------------------
# RefinementIteration dataclass
# ---------------------------------------------------------------------------


class TestRefinementIteration:
    def test_fields_accessible(self) -> None:
        it = RefinementIteration(
            feedback="deny delete",
            policy=_policy(),
            warnings=[],
            timestamp=1234567890.0,
        )
        assert it.feedback == "deny delete"
        assert it.policy == _policy()
        assert it.warnings == []
        assert it.timestamp == 1234567890.0

    def test_timestamp_defaults_to_current_time(self) -> None:
        import time

        before = time.time()
        it = RefinementIteration(feedback="f", policy={}, warnings=[])
        after = time.time()
        assert before <= it.timestamp <= after
