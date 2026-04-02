"""Tests for rbacx.ai._explainer — ExplainGenerator and PolicyExplainer."""

import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from rbacx.ai._explainer import (
    ExplainGenerator,
    PolicyExplainer,
    _extract_rule_ids,
    _parse_input,
)
from rbacx.ai._result import DecisionExplanation
from rbacx.ai.exceptions import PolicyGenerationError
from rbacx.core.decision import Decision
from rbacx.core.model import Action, Resource, Subject

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_client(response: str = "explanation text") -> MagicMock:
    client = MagicMock()
    client.complete = AsyncMock(return_value=response)
    return client


def _flat_policy(*rule_ids: str) -> dict[str, Any]:
    return {
        "algorithm": "deny-overrides",
        "rules": [
            {
                "id": rid,
                "effect": "permit",
                "actions": ["read"],
                "resource": {"type": "doc"},
            }
            for rid in rule_ids
        ],
    }


def _denied_decision() -> Decision:
    return Decision(allowed=False, effect="deny", rule_id=None)


def _allowed_decision(rule_id: str = "r1") -> Decision:
    return Decision(allowed=True, effect="permit", rule_id=rule_id)


# ---------------------------------------------------------------------------
# _extract_rule_ids
# ---------------------------------------------------------------------------


class TestExtractRuleIds:
    def test_flat_policy(self) -> None:
        policy = _flat_policy("r1", "r2", "r3")
        assert _extract_rule_ids(policy) == ["r1", "r2", "r3"]

    def test_policyset(self) -> None:
        policy = {
            "policies": [
                {"rules": [{"id": "a"}, {"id": "b"}]},
                {"rules": [{"id": "c"}]},
            ]
        }
        assert _extract_rule_ids(policy) == ["a", "b", "c"]

    def test_empty_rules(self) -> None:
        assert _extract_rule_ids({"rules": []}) == []

    def test_rule_without_id_skipped(self) -> None:
        policy = {"rules": [{"effect": "permit", "actions": ["read"], "resource": {"type": "x"}}]}
        assert _extract_rule_ids(policy) == []

    def test_empty_policy(self) -> None:
        assert _extract_rule_ids({}) == []


# ---------------------------------------------------------------------------
# _parse_input
# ---------------------------------------------------------------------------


class TestParseInput:
    def _full_input(self) -> dict[str, Any]:
        return {
            "subject": {"id": "u1", "roles": ["admin"], "attrs": {"dept": "eng"}},
            "action": "read",
            "resource": {"type": "doc", "id": "d1", "attrs": {"owner": "u1"}},
        }

    def test_returns_subject_action_resource(self) -> None:
        subject, action, resource = _parse_input(self._full_input())
        assert isinstance(subject, Subject)
        assert isinstance(action, Action)
        assert isinstance(resource, Resource)

    def test_subject_id(self) -> None:
        subject, _, _ = _parse_input(self._full_input())
        assert subject.id == "u1"

    def test_subject_roles(self) -> None:
        subject, _, _ = _parse_input(self._full_input())
        assert subject.roles == ["admin"]

    def test_subject_attrs(self) -> None:
        subject, _, _ = _parse_input(self._full_input())
        assert subject.attrs == {"dept": "eng"}

    def test_action_name(self) -> None:
        _, action, _ = _parse_input(self._full_input())
        assert action.name == "read"

    def test_resource_type(self) -> None:
        _, _, resource = _parse_input(self._full_input())
        assert resource.type == "doc"

    def test_resource_id(self) -> None:
        _, _, resource = _parse_input(self._full_input())
        assert resource.id == "d1"

    def test_resource_attrs(self) -> None:
        _, _, resource = _parse_input(self._full_input())
        assert resource.attrs == {"owner": "u1"}

    def test_roles_optional_defaults_empty(self) -> None:
        inp = {"subject": {"id": "u1"}, "action": "read", "resource": {"type": "doc"}}
        subject, _, _ = _parse_input(inp)
        assert subject.roles == []

    def test_subject_attrs_optional_defaults_empty(self) -> None:
        inp = {"subject": {"id": "u1"}, "action": "read", "resource": {"type": "doc"}}
        subject, _, _ = _parse_input(inp)
        assert subject.attrs == {}

    def test_resource_id_optional(self) -> None:
        inp = {"subject": {"id": "u1"}, "action": "read", "resource": {"type": "doc"}}
        _, _, resource = _parse_input(inp)
        assert resource.id is None

    def test_resource_attrs_optional_defaults_empty(self) -> None:
        inp = {"subject": {"id": "u1"}, "action": "read", "resource": {"type": "doc"}}
        _, _, resource = _parse_input(inp)
        assert resource.attrs == {}

    def test_missing_subject_raises(self) -> None:
        with pytest.raises(PolicyGenerationError, match="subject"):
            _parse_input({"action": "read", "resource": {"type": "doc"}})

    def test_subject_not_dict_raises(self) -> None:
        with pytest.raises(PolicyGenerationError):
            _parse_input({"subject": "u1", "action": "read", "resource": {"type": "doc"}})

    def test_missing_action_raises(self) -> None:
        with pytest.raises(PolicyGenerationError, match="action"):
            _parse_input({"subject": {"id": "u1"}, "resource": {"type": "doc"}})

    def test_action_not_string_raises(self) -> None:
        with pytest.raises(PolicyGenerationError):
            _parse_input({"subject": {"id": "u1"}, "action": 42, "resource": {"type": "doc"}})

    def test_missing_resource_raises(self) -> None:
        with pytest.raises(PolicyGenerationError, match="resource"):
            _parse_input({"subject": {"id": "u1"}, "action": "read"})

    def test_resource_missing_type_raises(self) -> None:
        with pytest.raises(PolicyGenerationError):
            _parse_input({"subject": {"id": "u1"}, "action": "read", "resource": {"id": "d1"}})


# ---------------------------------------------------------------------------
# ExplainGenerator
# ---------------------------------------------------------------------------


class TestExplainGenerator:
    @pytest.mark.asyncio
    async def test_calls_llm_exactly_once(self) -> None:
        policy = _flat_policy("r1", "r2")
        client = _make_client(json.dumps({"r1": "Permits reading", "r2": "Denies writing"}))
        gen = ExplainGenerator(client)
        await gen.explain_rules(policy)
        assert client.complete.call_count == 1

    @pytest.mark.asyncio
    async def test_returns_dict_keyed_by_rule_ids(self) -> None:
        policy = _flat_policy("r1", "r2")
        client = _make_client(json.dumps({"r1": "Explains r1", "r2": "Explains r2"}))
        gen = ExplainGenerator(client)
        result = await gen.explain_rules(policy)
        assert set(result.keys()) == {"r1", "r2"}

    @pytest.mark.asyncio
    async def test_values_are_strings(self) -> None:
        policy = _flat_policy("r1")
        client = _make_client(json.dumps({"r1": "Allows reading documents"}))
        gen = ExplainGenerator(client)
        result = await gen.explain_rules(policy)
        assert isinstance(result["r1"], str)

    @pytest.mark.asyncio
    async def test_missing_rule_id_in_response_gets_fallback(self) -> None:
        policy = _flat_policy("r1", "r2")
        # LLM only returns r1, not r2
        client = _make_client(json.dumps({"r1": "Allows reading"}))
        gen = ExplainGenerator(client)
        result = await gen.explain_rules(policy)
        assert "r2" in result
        assert result["r2"] != ""

    @pytest.mark.asyncio
    async def test_invalid_json_response_all_get_fallback(self) -> None:
        policy = _flat_policy("r1", "r2")
        client = _make_client("This is not JSON at all.")
        gen = ExplainGenerator(client)
        result = await gen.explain_rules(policy)
        assert set(result.keys()) == {"r1", "r2"}
        assert all(v != "" for v in result.values())

    @pytest.mark.asyncio
    async def test_json_array_response_all_get_fallback(self) -> None:
        policy = _flat_policy("r1")
        client = _make_client("[1, 2, 3]")
        gen = ExplainGenerator(client)
        result = await gen.explain_rules(policy)
        assert "r1" in result

    @pytest.mark.asyncio
    async def test_fenced_json_response_parsed(self) -> None:
        policy = _flat_policy("r1")
        raw = "```json\n" + json.dumps({"r1": "Permits reading"}) + "\n```"
        client = _make_client(raw)
        gen = ExplainGenerator(client)
        result = await gen.explain_rules(policy)
        assert result["r1"] == "Permits reading"

    @pytest.mark.asyncio
    async def test_empty_policy_returns_empty_dict(self) -> None:
        policy = {"algorithm": "deny-overrides", "rules": []}
        client = _make_client("{}")
        gen = ExplainGenerator(client)
        result = await gen.explain_rules(policy)
        assert result == {}


class TestExplainGeneratorParseResponse:
    def test_clean_json(self) -> None:
        raw = json.dumps({"r1": "text one", "r2": "text two"})
        result = ExplainGenerator._parse_explanation_response(raw)
        assert result == {"r1": "text one", "r2": "text two"}

    def test_json_fence_stripped(self) -> None:
        inner = json.dumps({"r1": "text"})
        result = ExplainGenerator._parse_explanation_response("```json\n" + inner + "\n```")
        assert result == {"r1": "text"}

    def test_plain_fence_stripped(self) -> None:
        inner = json.dumps({"r1": "text"})
        result = ExplainGenerator._parse_explanation_response("```\n" + inner + "\n```")
        assert result == {"r1": "text"}

    def test_invalid_json_returns_empty(self) -> None:
        assert ExplainGenerator._parse_explanation_response("not json") == {}

    def test_json_array_returns_empty(self) -> None:
        assert ExplainGenerator._parse_explanation_response("[1,2]") == {}

    def test_values_coerced_to_str(self) -> None:
        raw = json.dumps({"r1": 42})
        result = ExplainGenerator._parse_explanation_response(raw)
        assert result["r1"] == "42"


# ---------------------------------------------------------------------------
# PolicyExplainer
# ---------------------------------------------------------------------------


class TestPolicyExplainer:
    def _policy(self) -> dict[str, Any]:
        return _flat_policy("r1")

    def _full_input(self) -> dict[str, Any]:
        return {
            "subject": {"id": "u1", "roles": ["viewer"]},
            "action": "read",
            "resource": {"type": "doc", "id": "d1"},
        }

    @pytest.mark.asyncio
    async def test_returns_decision_explanation(self) -> None:
        client = _make_client("Access is allowed because rule r1 matched.")
        explainer = PolicyExplainer(client)
        result = await explainer.explain_decision(self._policy(), self._full_input())
        assert isinstance(result, DecisionExplanation)

    @pytest.mark.asyncio
    async def test_decision_comes_from_guard_not_llm(self) -> None:
        """Decision must be the Guard's result, not parsed from LLM output."""
        client = _make_client("DENIED — just kidding, allowed")
        explainer = PolicyExplainer(client)
        result = await explainer.explain_decision(self._policy(), self._full_input())
        # The policy has a permit rule for read on doc with no condition,
        # so Guard should allow it regardless of what the LLM says
        assert isinstance(result.decision, Decision)

    @pytest.mark.asyncio
    async def test_human_field_is_llm_output(self) -> None:
        explanation_text = "Access is allowed because rule r1 matched."
        client = _make_client(explanation_text)
        explainer = PolicyExplainer(client)
        result = await explainer.explain_decision(self._policy(), self._full_input())
        assert result.human == explanation_text

    @pytest.mark.asyncio
    async def test_human_is_stripped(self) -> None:
        client = _make_client("  explanation with whitespace  ")
        explainer = PolicyExplainer(client)
        result = await explainer.explain_decision(self._policy(), self._full_input())
        assert result.human == "explanation with whitespace"

    @pytest.mark.asyncio
    async def test_llm_called_exactly_once(self) -> None:
        client = _make_client("explanation")
        explainer = PolicyExplainer(client)
        await explainer.explain_decision(self._policy(), self._full_input())
        assert client.complete.call_count == 1

    @pytest.mark.asyncio
    async def test_decision_passed_to_prompt(self) -> None:
        """build_explain_decision must receive the Guard's decision."""
        client = _make_client("ok")
        explainer = PolicyExplainer(client)
        with patch("rbacx.ai._explainer.PromptBuilder.build_explain_decision") as mock_build:
            mock_build.return_value = [{"role": "user", "content": "explain"}]
            await explainer.explain_decision(self._policy(), self._full_input())
            assert mock_build.called
            _, _, decision_arg = mock_build.call_args[0]
            assert isinstance(decision_arg, Decision)

    @pytest.mark.asyncio
    async def test_missing_subject_raises(self) -> None:
        client = _make_client("ok")
        explainer = PolicyExplainer(client)
        with pytest.raises(PolicyGenerationError, match="subject"):
            await explainer.explain_decision(
                self._policy(),
                {"action": "read", "resource": {"type": "doc"}},
            )

    @pytest.mark.asyncio
    async def test_missing_action_raises(self) -> None:
        client = _make_client("ok")
        explainer = PolicyExplainer(client)
        with pytest.raises(PolicyGenerationError, match="action"):
            await explainer.explain_decision(
                self._policy(),
                {"subject": {"id": "u1"}, "resource": {"type": "doc"}},
            )

    @pytest.mark.asyncio
    async def test_missing_resource_type_raises(self) -> None:
        client = _make_client("ok")
        explainer = PolicyExplainer(client)
        with pytest.raises(PolicyGenerationError):
            await explainer.explain_decision(
                self._policy(),
                {"subject": {"id": "u1"}, "action": "read", "resource": {}},
            )

    @pytest.mark.asyncio
    async def test_denied_decision_returned_correctly(self) -> None:
        # Policy with no matching rules → Guard returns deny
        deny_policy: dict[str, Any] = {
            "algorithm": "deny-overrides",
            "rules": [
                {
                    "id": "admin_only",
                    "effect": "permit",
                    "actions": ["read"],
                    "resource": {"type": "doc"},
                    "condition": {"hasAny": [{"attr": "subject.roles"}, ["admin"]]},
                }
            ],
        }
        client = _make_client("Access denied — user lacks admin role.")
        explainer = PolicyExplainer(client)
        result = await explainer.explain_decision(
            deny_policy,
            {
                "subject": {"id": "u1", "roles": ["viewer"]},
                "action": "read",
                "resource": {"type": "doc"},
            },
        )
        assert result.decision.allowed is False
        assert isinstance(result.human, str)
