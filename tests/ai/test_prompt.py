"""Tests for rbacx.ai._prompt.PromptBuilder."""

import json
from pathlib import Path
from typing import Any

from rbacx.ai._prompt import _SYSTEM_PROMPT, PromptBuilder
from rbacx.ai._schema_parser import NormalizedSchema
from rbacx.core.decision import Decision

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _decision(
    allowed: bool = True,
    effect: str = "permit",
    rule_id: str | None = "task_read",
) -> Decision:
    return Decision(allowed=allowed, effect=effect, rule_id=rule_id)


# ---------------------------------------------------------------------------
# System prompt file
# ---------------------------------------------------------------------------


class TestSystemPromptFile:
    def test_system_prompt_is_non_empty(self) -> None:
        assert len(_SYSTEM_PROMPT.strip()) > 0

    def test_system_prompt_contains_dsl_keywords(self) -> None:
        assert "permit" in _SYSTEM_PROMPT
        assert "deny" in _SYSTEM_PROMPT
        assert "condition" in _SYSTEM_PROMPT

    def test_system_prompt_contains_operators(self) -> None:
        assert "hasAny" in _SYSTEM_PROMPT
        assert "hasAll" in _SYSTEM_PROMPT

    def test_system_prompt_contains_output_rules(self) -> None:
        # Must instruct model to return only JSON
        assert "JSON" in _SYSTEM_PROMPT

    def test_system_md_file_exists(self) -> None:
        prompts_dir = Path(__file__).parent.parent.parent / "src" / "rbacx" / "ai" / "_prompts"
        assert (prompts_dir / "system.md").exists()

    def test_example_schema_json_exists_and_valid(self) -> None:
        examples_dir = (
            Path(__file__).parent.parent.parent / "src" / "rbacx" / "ai" / "_prompts" / "examples"
        )
        schema_path = examples_dir / "schema.json"
        assert schema_path.exists()
        data = json.loads(schema_path.read_text(encoding="utf-8"))
        assert "openapi" in data or "swagger" in data

    def test_example_policy_json_exists_and_valid(self) -> None:
        examples_dir = (
            Path(__file__).parent.parent.parent / "src" / "rbacx" / "ai" / "_prompts" / "examples"
        )
        policy_path = examples_dir / "policy.json"
        assert policy_path.exists()
        data = json.loads(policy_path.read_text(encoding="utf-8"))
        assert "rules" in data
        assert isinstance(data["rules"], list)
        assert len(data["rules"]) > 0


# ---------------------------------------------------------------------------
# build_generation
# ---------------------------------------------------------------------------


class TestBuildGeneration:
    def test_returns_two_messages(self, sample_normalized_schema: NormalizedSchema) -> None:
        msgs = PromptBuilder.build_generation(sample_normalized_schema)
        assert len(msgs) == 2

    def test_first_is_system(self, sample_normalized_schema: NormalizedSchema) -> None:
        msgs = PromptBuilder.build_generation(sample_normalized_schema)
        assert msgs[0]["role"] == "system"

    def test_second_is_user(self, sample_normalized_schema: NormalizedSchema) -> None:
        msgs = PromptBuilder.build_generation(sample_normalized_schema)
        assert msgs[1]["role"] == "user"

    def test_system_content_is_dsl_spec(self, sample_normalized_schema: NormalizedSchema) -> None:
        msgs = PromptBuilder.build_generation(sample_normalized_schema)
        assert "permit" in msgs[0]["content"]
        assert "deny" in msgs[0]["content"]

    def test_user_content_contains_schema_repr(
        self, sample_normalized_schema: NormalizedSchema
    ) -> None:
        msgs = PromptBuilder.build_generation(sample_normalized_schema)
        user = msgs[1]["content"]
        assert "task" in user
        assert "project" in user

    def test_context_included_when_provided(
        self, sample_normalized_schema: NormalizedSchema
    ) -> None:
        msgs = PromptBuilder.build_generation(
            sample_normalized_schema, context="SaaS B2B, tenant isolation"
        )
        user = msgs[1]["content"]
        assert "SaaS B2B" in user
        assert "tenant isolation" in user

    def test_context_absent_when_empty(self, sample_normalized_schema: NormalizedSchema) -> None:
        msgs = PromptBuilder.build_generation(sample_normalized_schema, context="")
        user = msgs[1]["content"]
        assert "Additional context" not in user

    def test_context_absent_when_whitespace(
        self, sample_normalized_schema: NormalizedSchema
    ) -> None:
        msgs = PromptBuilder.build_generation(sample_normalized_schema, context="   ")
        user = msgs[1]["content"]
        assert "Additional context" not in user

    def test_user_contains_json_instruction(
        self, sample_normalized_schema: NormalizedSchema
    ) -> None:
        msgs = PromptBuilder.build_generation(sample_normalized_schema)
        assert "JSON" in msgs[1]["content"]


# ---------------------------------------------------------------------------
# build_fix
# ---------------------------------------------------------------------------


class TestBuildFix:
    def _prev(self) -> list[dict[str, str]]:
        return [
            {"role": "system", "content": "spec"},
            {"role": "user", "content": "generate"},
        ]

    def test_length_is_prev_plus_two(self) -> None:
        prev = self._prev()
        msgs = PromptBuilder.build_fix(prev, raw_policy='{"bad":true}', validation_errors=["e1"])
        assert len(msgs) == len(prev) + 2

    def test_second_to_last_is_assistant(self) -> None:
        msgs = PromptBuilder.build_fix(
            self._prev(), raw_policy='{"bad":true}', validation_errors=["e1"]
        )
        assert msgs[-2]["role"] == "assistant"

    def test_last_is_user(self) -> None:
        msgs = PromptBuilder.build_fix(
            self._prev(), raw_policy='{"bad":true}', validation_errors=["e1"]
        )
        assert msgs[-1]["role"] == "user"

    def test_assistant_content_is_raw_policy(self) -> None:
        raw = '{"broken": true}'
        msgs = PromptBuilder.build_fix(self._prev(), raw_policy=raw, validation_errors=[])
        assert msgs[-2]["content"] == raw

    def test_user_content_contains_errors(self) -> None:
        errors = ["rules is required", "effect must be permit or deny"]
        msgs = PromptBuilder.build_fix(self._prev(), raw_policy="{}", validation_errors=errors)
        user_content = msgs[-1]["content"]
        assert "rules is required" in user_content
        assert "effect must be permit or deny" in user_content

    def test_previous_messages_preserved(self) -> None:
        prev = self._prev()
        msgs = PromptBuilder.build_fix(prev, raw_policy="{}", validation_errors=[])
        assert msgs[0] == prev[0]
        assert msgs[1] == prev[1]

    def test_empty_errors_list(self) -> None:
        msgs = PromptBuilder.build_fix(self._prev(), raw_policy="{}", validation_errors=[])
        # Should still produce a valid messages list
        assert len(msgs) == len(self._prev()) + 2


# ---------------------------------------------------------------------------
# build_refine
# ---------------------------------------------------------------------------


class TestBuildRefine:
    def test_length_is_history_plus_two(self, valid_policy_dict: dict[str, Any]) -> None:
        history: list[dict[str, str]] = [{"role": "system", "content": "spec"}]
        msgs = PromptBuilder.build_refine(history, valid_policy_dict, "deny delete for viewers")
        assert len(msgs) == len(history) + 2

    def test_empty_history_gives_two_messages(self, valid_policy_dict: dict[str, Any]) -> None:
        msgs = PromptBuilder.build_refine([], valid_policy_dict, "some feedback")
        assert len(msgs) == 2

    def test_second_to_last_is_assistant_with_policy(
        self, valid_policy_dict: dict[str, Any]
    ) -> None:
        msgs = PromptBuilder.build_refine([], valid_policy_dict, "feedback")
        assert msgs[-2]["role"] == "assistant"
        parsed = json.loads(msgs[-2]["content"])
        assert "rules" in parsed

    def test_last_is_user_with_feedback(self, valid_policy_dict: dict[str, Any]) -> None:
        msgs = PromptBuilder.build_refine([], valid_policy_dict, "deny delete for viewers")
        assert msgs[-1]["role"] == "user"
        assert "deny delete for viewers" in msgs[-1]["content"]

    def test_history_preserved(self, valid_policy_dict: dict[str, Any]) -> None:
        history = [
            {"role": "system", "content": "spec"},
            {"role": "user", "content": "original request"},
        ]
        msgs = PromptBuilder.build_refine(history, valid_policy_dict, "refine")
        assert msgs[0] == history[0]
        assert msgs[1] == history[1]

    def test_user_contains_json_instruction(self, valid_policy_dict: dict[str, Any]) -> None:
        msgs = PromptBuilder.build_refine([], valid_policy_dict, "feedback")
        assert "JSON" in msgs[-1]["content"]


# ---------------------------------------------------------------------------
# build_explain_rules
# ---------------------------------------------------------------------------


class TestBuildExplainRules:
    def test_returns_two_messages(self, valid_policy_dict: dict[str, Any]) -> None:
        msgs = PromptBuilder.build_explain_rules(valid_policy_dict)
        assert len(msgs) == 2

    def test_first_is_system(self, valid_policy_dict: dict[str, Any]) -> None:
        assert PromptBuilder.build_explain_rules(valid_policy_dict)[0]["role"] == "system"

    def test_second_is_user(self, valid_policy_dict: dict[str, Any]) -> None:
        assert PromptBuilder.build_explain_rules(valid_policy_dict)[1]["role"] == "user"

    def test_user_contains_policy(self, valid_policy_dict: dict[str, Any]) -> None:
        msgs = PromptBuilder.build_explain_rules(valid_policy_dict)
        # The serialised policy must appear in the user message
        assert "task_read" in msgs[1]["content"]

    def test_user_instructs_json_output(self, valid_policy_dict: dict[str, Any]) -> None:
        msgs = PromptBuilder.build_explain_rules(valid_policy_dict)
        assert "JSON" in msgs[1]["content"]


# ---------------------------------------------------------------------------
# build_explain_decision
# ---------------------------------------------------------------------------


class TestBuildExplainDecision:
    def test_returns_two_messages(self, valid_policy_dict: dict[str, Any]) -> None:
        d = _decision()
        msgs = PromptBuilder.build_explain_decision(valid_policy_dict, {}, d)
        assert len(msgs) == 2

    def test_first_is_system(self, valid_policy_dict: dict[str, Any]) -> None:
        msgs = PromptBuilder.build_explain_decision(valid_policy_dict, {}, _decision())
        assert msgs[0]["role"] == "system"

    def test_user_contains_allowed_outcome(self, valid_policy_dict: dict[str, Any]) -> None:
        msgs = PromptBuilder.build_explain_decision(
            valid_policy_dict, {"action": "read"}, _decision(allowed=True)
        )
        assert "ALLOWED" in msgs[1]["content"]

    def test_user_contains_denied_outcome(self, valid_policy_dict: dict[str, Any]) -> None:
        msgs = PromptBuilder.build_explain_decision(
            valid_policy_dict, {}, _decision(allowed=False, effect="deny", rule_id=None)
        )
        assert "DENIED" in msgs[1]["content"]

    def test_user_contains_rule_id(self, valid_policy_dict: dict[str, Any]) -> None:
        msgs = PromptBuilder.build_explain_decision(
            valid_policy_dict, {}, _decision(rule_id="task_read")
        )
        assert "task_read" in msgs[1]["content"]

    def test_user_contains_input_attrs(self, valid_policy_dict: dict[str, Any]) -> None:
        input_attrs = {"subject": {"id": "u1"}, "action": "read"}
        msgs = PromptBuilder.build_explain_decision(valid_policy_dict, input_attrs, _decision())
        assert "u1" in msgs[1]["content"]

    def test_no_rule_id_shows_no_match(self, valid_policy_dict: dict[str, Any]) -> None:
        msgs = PromptBuilder.build_explain_decision(valid_policy_dict, {}, _decision(rule_id=None))
        assert "No rule matched" in msgs[1]["content"]
