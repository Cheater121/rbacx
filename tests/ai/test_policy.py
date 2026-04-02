"""Tests for rbacx.ai.policy.AIPolicy — integration tests with mocked LLM."""

import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from rbacx.ai._result import DecisionExplanation, PolicyResult
from rbacx.ai.exceptions import PolicyGenerationError
from rbacx.ai.policy import AIPolicy
from rbacx.core.decision import Decision

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_VALID_POLICY: dict[str, Any] = {
    "algorithm": "deny-overrides",
    "rules": [
        {
            "id": "r1",
            "effect": "permit",
            "actions": ["read"],
            "resource": {"type": "doc"},
        }
    ],
}
_VALID_RAW = json.dumps(_VALID_POLICY)

_OPENAPI3: dict[str, Any] = {
    "openapi": "3.0.0",
    "info": {"title": "TestAPI", "version": "1.0.0"},
    "paths": {
        "/docs": {
            "get": {
                "tags": ["doc"],
                "responses": {"200": {"description": "OK"}, "401": {"description": "Unauth"}},
            }
        }
    },
}


def _make_ai(llm_response: str = _VALID_RAW) -> tuple[AIPolicy, MagicMock]:
    """Return (AIPolicy, mock_openai_instance) with patched LLMClient."""
    mock_openai_inst = MagicMock()
    mock_openai_inst.chat.completions.create = AsyncMock(
        return_value=_make_completion(llm_response)
    )
    with patch("rbacx.ai._client.AsyncOpenAI", return_value=mock_openai_inst):
        ai = AIPolicy(api_key="sk-test", model="gpt-4o")
    return ai, mock_openai_inst


def _make_completion(content: str) -> MagicMock:
    msg = MagicMock()
    msg.content = content
    choice = MagicMock()
    choice.message = msg
    resp = MagicMock()
    resp.choices = [choice]
    return resp


def _patch_validate(return_value: list[str] | None = None):
    return patch(
        "rbacx.ai._generator.PolicyValidator.validate",
        return_value=return_value or [],
    )


# ---------------------------------------------------------------------------
# AIPolicy.__init__
# ---------------------------------------------------------------------------


class TestAIPolicyInit:
    def test_base_url_none_not_forwarded(self) -> None:
        with patch("rbacx.ai._client.AsyncOpenAI") as mock_cls:
            mock_cls.return_value = MagicMock()
            AIPolicy(api_key="sk-test", model="gpt-4o", base_url=None)
            _, kwargs = mock_cls.call_args
            assert "base_url" not in kwargs

    def test_base_url_forwarded(self) -> None:
        url = "https://openrouter.ai/api/v1"
        with patch("rbacx.ai._client.AsyncOpenAI") as mock_cls:
            mock_cls.return_value = MagicMock()
            AIPolicy(api_key="sk-test", model="gpt-4o", base_url=url)
            _, kwargs = mock_cls.call_args
            assert kwargs.get("base_url") == url

    def test_no_session_initially(self) -> None:
        with patch("rbacx.ai._client.AsyncOpenAI", return_value=MagicMock()):
            ai = AIPolicy(api_key="sk-test", model="gpt-4o")
        assert ai._session is None


# ---------------------------------------------------------------------------
# from_schema
# ---------------------------------------------------------------------------


class TestFromSchema:
    @pytest.mark.asyncio
    async def test_dict_schema_returns_policy_result(self) -> None:
        ai, _ = _make_ai(_VALID_RAW)
        with _patch_validate():
            result = await ai.from_schema(_OPENAPI3)
        assert isinstance(result, PolicyResult)

    @pytest.mark.asyncio
    async def test_dsl_matches_generated_policy(self) -> None:
        ai, _ = _make_ai(_VALID_RAW)
        with _patch_validate():
            result = await ai.from_schema(_OPENAPI3)
        assert result.dsl == _VALID_POLICY

    @pytest.mark.asyncio
    async def test_json_file_path(self, tmp_path: Path) -> None:
        p = tmp_path / "schema.json"
        p.write_text(json.dumps(_OPENAPI3))
        ai, _ = _make_ai(_VALID_RAW)
        with _patch_validate():
            result = await ai.from_schema(p)
        assert isinstance(result, PolicyResult)

    @pytest.mark.asyncio
    async def test_json_file_string_path(self, tmp_path: Path) -> None:
        p = tmp_path / "schema.json"
        p.write_text(json.dumps(_OPENAPI3))
        ai, _ = _make_ai(_VALID_RAW)
        with _patch_validate():
            result = await ai.from_schema(str(p))
        assert isinstance(result, PolicyResult)

    @pytest.mark.asyncio
    async def test_yaml_file_path(self, tmp_path: Path) -> None:
        yaml = pytest.importorskip("yaml")
        p = tmp_path / "schema.yaml"
        p.write_text(yaml.dump(_OPENAPI3))
        ai, _ = _make_ai(_VALID_RAW)
        with _patch_validate():
            result = await ai.from_schema(p)
        assert isinstance(result, PolicyResult)

    @pytest.mark.asyncio
    async def test_compile_true_returns_compiled(self) -> None:
        ai, _ = _make_ai(_VALID_RAW)
        fake_compiled = object()
        with _patch_validate():
            with patch.object(AIPolicy, "_compile", return_value=fake_compiled):
                result = await ai.from_schema(_OPENAPI3, compile=True)
        assert result.compiled is fake_compiled

    @pytest.mark.asyncio
    async def test_compile_false_compiled_is_none(self) -> None:
        ai, _ = _make_ai(_VALID_RAW)
        with _patch_validate():
            result = await ai.from_schema(_OPENAPI3, compile=False)
        assert result.compiled is None

    @pytest.mark.asyncio
    async def test_compile_true_unavailable_raises(self) -> None:
        ai, _ = _make_ai(_VALID_RAW)
        with _patch_validate():
            with patch.object(
                AIPolicy,
                "_compile",
                side_effect=PolicyGenerationError("compiler unavailable"),
            ):
                with pytest.raises(PolicyGenerationError, match="compiler"):
                    await ai.from_schema(_OPENAPI3, compile=True)

    @pytest.mark.asyncio
    async def test_explain_true_returns_explanation(self) -> None:
        ai, mock_openai = _make_ai(_VALID_RAW)
        # Second LLM call returns explanation JSON
        explain_raw = json.dumps({"r1": "Permits reading documents"})
        mock_openai.chat.completions.create = AsyncMock(
            side_effect=[
                _make_completion(_VALID_RAW),
                _make_completion(explain_raw),
            ]
        )
        with _patch_validate():
            result = await ai.from_schema(_OPENAPI3, explain=True)
        assert result.explanation is not None
        assert "r1" in result.explanation

    @pytest.mark.asyncio
    async def test_explain_false_explanation_is_none(self) -> None:
        ai, _ = _make_ai(_VALID_RAW)
        with _patch_validate():
            result = await ai.from_schema(_OPENAPI3, explain=False)
        assert result.explanation is None

    @pytest.mark.asyncio
    async def test_raw_true_includes_raw_output(self) -> None:
        ai, _ = _make_ai(_VALID_RAW)
        with _patch_validate():
            result = await ai.from_schema(_OPENAPI3, raw=True)
        assert result.raw == _VALID_RAW

    @pytest.mark.asyncio
    async def test_raw_false_raw_is_none(self) -> None:
        ai, _ = _make_ai(_VALID_RAW)
        with _patch_validate():
            result = await ai.from_schema(_OPENAPI3, raw=False)
        assert result.raw is None

    @pytest.mark.asyncio
    async def test_creates_refinement_session(self) -> None:
        ai, _ = _make_ai(_VALID_RAW)
        assert ai._session is None
        with _patch_validate():
            await ai.from_schema(_OPENAPI3)
        assert ai._session is not None

    @pytest.mark.asyncio
    async def test_repeated_from_schema_resets_session(self) -> None:
        mock_openai = MagicMock()
        mock_openai.chat.completions.create = AsyncMock(
            side_effect=[
                _make_completion(_VALID_RAW),
                _make_completion(_VALID_RAW),
            ]
        )
        with patch("rbacx.ai._client.AsyncOpenAI", return_value=mock_openai):
            ai = AIPolicy(api_key="sk-test", model="gpt-4o")

        with _patch_validate():
            await ai.from_schema(_OPENAPI3)
            session_first = ai._session
            await ai.from_schema(_OPENAPI3)
            session_second = ai._session

        assert session_first is not session_second

    @pytest.mark.asyncio
    async def test_context_passed_to_prompt(self) -> None:
        ai, _ = _make_ai(_VALID_RAW)
        with _patch_validate():
            with patch("rbacx.ai.policy.PromptBuilder.build_generation") as mock_build:
                mock_build.return_value = [{"role": "user", "content": "gen"}]
                await ai.from_schema(_OPENAPI3, context="SaaS B2B")
        mock_build.assert_called_once()
        _, kwargs = mock_build.call_args
        assert kwargs.get("context") == "SaaS B2B" or mock_build.call_args[0][1] == "SaaS B2B"


# ---------------------------------------------------------------------------
# refine_policy
# ---------------------------------------------------------------------------


class TestRefinePolicy:
    @pytest.mark.asyncio
    async def test_raises_runtime_error_without_from_schema(self) -> None:
        with patch("rbacx.ai._client.AsyncOpenAI", return_value=MagicMock()):
            ai = AIPolicy(api_key="sk-test", model="gpt-4o")
        with pytest.raises(RuntimeError, match="from_schema"):
            await ai.refine_policy("some feedback")

    @pytest.mark.asyncio
    async def test_no_error_with_explicit_policy(self) -> None:
        """refine_policy(policy=...) must work without prior from_schema."""
        mock_openai = MagicMock()
        mock_openai.chat.completions.create = AsyncMock(return_value=_make_completion(_VALID_RAW))
        with patch("rbacx.ai._client.AsyncOpenAI", return_value=mock_openai):
            ai = AIPolicy(api_key="sk-test", model="gpt-4o")
        with _patch_validate():
            result = await ai.refine_policy("feedback", policy=_VALID_POLICY)
        assert isinstance(result, PolicyResult)

    @pytest.mark.asyncio
    async def test_returns_policy_result_after_from_schema(self) -> None:
        mock_openai = MagicMock()
        mock_openai.chat.completions.create = AsyncMock(
            side_effect=[
                _make_completion(_VALID_RAW),  # from_schema
                _make_completion(_VALID_RAW),  # refine_policy
            ]
        )
        with patch("rbacx.ai._client.AsyncOpenAI", return_value=mock_openai):
            ai = AIPolicy(api_key="sk-test", model="gpt-4o")
        with _patch_validate():
            await ai.from_schema(_OPENAPI3)
            result = await ai.refine_policy("deny delete for viewers")
        assert isinstance(result, PolicyResult)

    @pytest.mark.asyncio
    async def test_explicit_policy_resets_session(self) -> None:
        mock_openai = MagicMock()
        mock_openai.chat.completions.create = AsyncMock(
            side_effect=[
                _make_completion(_VALID_RAW),  # from_schema
                _make_completion(_VALID_RAW),  # refine with policy=
            ]
        )
        with patch("rbacx.ai._client.AsyncOpenAI", return_value=mock_openai):
            ai = AIPolicy(api_key="sk-test", model="gpt-4o")
        with _patch_validate():
            await ai.from_schema(_OPENAPI3)
            session_after_from = ai._session
            await ai.refine_policy("feedback", policy=_VALID_POLICY)
            session_after_refine = ai._session
        assert session_after_from is not session_after_refine

    @pytest.mark.asyncio
    async def test_repeated_refine_passes_history(self) -> None:
        mock_openai = MagicMock()
        mock_openai.chat.completions.create = AsyncMock(
            side_effect=[
                _make_completion(_VALID_RAW),  # from_schema
                _make_completion(_VALID_RAW),  # refine 1
                _make_completion(_VALID_RAW),  # refine 2
            ]
        )
        with patch("rbacx.ai._client.AsyncOpenAI", return_value=mock_openai):
            ai = AIPolicy(api_key="sk-test", model="gpt-4o")
        with _patch_validate():
            await ai.from_schema(_OPENAPI3)
            await ai.refine_policy("first feedback")
            len(
                mock_openai.chat.completions.create.call_args_list[1][1].get("messages")
                or mock_openai.chat.completions.create.call_args_list[1][0][0]
                if mock_openai.chat.completions.create.call_args_list[1][0]
                else []
            )
            await ai.refine_policy("second feedback")
        # Session history should have 2 entries
        assert len(ai._session.history) == 2

    @pytest.mark.asyncio
    async def test_compile_true_in_refine(self) -> None:
        mock_openai = MagicMock()
        mock_openai.chat.completions.create = AsyncMock(
            side_effect=[
                _make_completion(_VALID_RAW),
                _make_completion(_VALID_RAW),
            ]
        )
        with patch("rbacx.ai._client.AsyncOpenAI", return_value=mock_openai):
            ai = AIPolicy(api_key="sk-test", model="gpt-4o")
        fake = object()
        with _patch_validate():
            await ai.from_schema(_OPENAPI3)
            with patch(
                "rbacx.ai._refinement.RefinementSession._compile",
                return_value=fake,
            ):
                result = await ai.refine_policy("feedback", compile=True)
        assert result.compiled is fake


# ---------------------------------------------------------------------------
# explain_decision
# ---------------------------------------------------------------------------


class TestExplainDecision:
    def _input(self) -> dict[str, Any]:
        return {
            "subject": {"id": "u1", "roles": ["viewer"]},
            "action": "read",
            "resource": {"type": "doc", "id": "d1"},
        }

    @pytest.mark.asyncio
    async def test_returns_decision_explanation(self) -> None:
        ai, mock_openai = _make_ai("Access allowed because r1 matched.")
        result = await ai.explain_decision(_VALID_POLICY, self._input())
        assert isinstance(result, DecisionExplanation)

    @pytest.mark.asyncio
    async def test_human_is_llm_output(self) -> None:
        explanation = "Access allowed because the permit rule matched."
        ai, _ = _make_ai(explanation)
        result = await ai.explain_decision(_VALID_POLICY, self._input())
        assert result.human == explanation

    @pytest.mark.asyncio
    async def test_decision_is_from_guard(self) -> None:
        ai, _ = _make_ai("some explanation")
        result = await ai.explain_decision(_VALID_POLICY, self._input())
        assert isinstance(result.decision, Decision)

    @pytest.mark.asyncio
    async def test_malformed_input_raises(self) -> None:
        ai, _ = _make_ai("ok")
        with pytest.raises(PolicyGenerationError):
            await ai.explain_decision(
                _VALID_POLICY,
                {"action": "read", "resource": {"type": "doc"}},  # no subject
            )

    @pytest.mark.asyncio
    async def test_independent_of_session(self) -> None:
        """explain_decision must work without any prior from_schema call."""
        with patch("rbacx.ai._client.AsyncOpenAI", return_value=MagicMock()) as mock_cls:
            mock_inst = MagicMock()
            mock_inst.chat.completions.create = AsyncMock(
                return_value=_make_completion("explanation")
            )
            mock_cls.return_value = mock_inst
            ai = AIPolicy(api_key="sk-test", model="gpt-4o")
        assert ai._session is None
        result = await ai.explain_decision(_VALID_POLICY, self._input())
        assert isinstance(result, DecisionExplanation)
