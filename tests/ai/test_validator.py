"""Tests for rbacx.ai._validator.PolicyValidator."""

from typing import Any
from unittest.mock import patch

import pytest

from rbacx.ai._validator import PolicyValidator

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


def _minimal_valid() -> dict[str, Any]:
    return {
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


def _policy_without_rules() -> dict[str, Any]:
    return {"algorithm": "deny-overrides"}


def _policy_bad_effect() -> dict[str, Any]:
    return {
        "rules": [
            {
                "id": "r1",
                "effect": "permitt",  # typo
                "actions": ["read"],
                "resource": {"type": "doc"},
            }
        ]
    }


def _policy_empty_actions() -> dict[str, Any]:
    return {
        "rules": [
            {
                "id": "r1",
                "effect": "permit",
                "actions": [],  # minItems: 1 violated
                "resource": {"type": "doc"},
            }
        ]
    }


def _policy_with_duplicate_ids() -> dict[str, Any]:
    """Lint should flag duplicate rule IDs."""
    return {
        "rules": [
            {"id": "dup", "effect": "permit", "actions": ["read"], "resource": {"type": "doc"}},
            {"id": "dup", "effect": "permit", "actions": ["read"], "resource": {"type": "doc"}},
        ]
    }


# ---------------------------------------------------------------------------
# validate()
# ---------------------------------------------------------------------------


class TestValidate:
    def test_valid_policy_returns_empty_list(self) -> None:
        pytest.importorskip("jsonschema")
        errors = PolicyValidator.validate(_minimal_valid())
        assert errors == []

    def test_missing_rules_key_returns_errors(self) -> None:
        # jsonschema required: either "rules" or "policies"
        errors = PolicyValidator.validate(_policy_without_rules())
        assert len(errors) > 0

    def test_bad_effect_returns_errors(self) -> None:
        pytest.importorskip("jsonschema")
        errors = PolicyValidator.validate(_policy_bad_effect())
        assert len(errors) > 0

    def test_empty_actions_returns_errors(self) -> None:
        pytest.importorskip("jsonschema")
        errors = PolicyValidator.validate(_policy_empty_actions())
        assert len(errors) > 0

    def test_errors_are_strings(self) -> None:
        errors = PolicyValidator.validate(_policy_without_rules())
        assert all(isinstance(e, str) for e in errors)

    def test_errors_contain_field_info(self) -> None:
        pytest.importorskip("jsonschema")
        errors = PolicyValidator.validate(_policy_bad_effect())
        combined = " ".join(errors)
        # Either the path or the message must reference "effect"
        assert "effect" in combined or "permitt" in combined

    def test_validate_without_jsonschema_returns_error(self) -> None:
        """When jsonschema is not installed, validate must still return errors."""
        with patch("rbacx.dsl.validate.validate_policy", side_effect=RuntimeError("no jsonschema")):
            errors = PolicyValidator.validate(_policy_without_rules())
            assert len(errors) > 0

    def test_returns_list_type(self) -> None:
        result = PolicyValidator.validate(_minimal_valid())
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# lint()
# ---------------------------------------------------------------------------


class TestLint:
    def test_clean_policy_returns_empty_list(self) -> None:
        issues = PolicyValidator.lint(_minimal_valid())
        assert isinstance(issues, list)

    def test_duplicate_ids_returns_issue(self) -> None:
        issues = PolicyValidator.lint(_policy_with_duplicate_ids())
        [i.get("code", "") for i in issues]
        # At least one issue should be raised for duplicate rule ids
        assert len(issues) > 0, f"Expected lint issues for duplicate ids, got: {issues}"

    def test_returns_list_of_dicts(self) -> None:
        issues = PolicyValidator.lint(_minimal_valid())
        assert isinstance(issues, list)
        for issue in issues:
            assert isinstance(issue, dict)

    def test_issue_has_code_key(self) -> None:
        issues = PolicyValidator.lint(_policy_with_duplicate_ids())
        if issues:
            assert "code" in issues[0]


# ---------------------------------------------------------------------------
# format_errors_for_prompt()
# ---------------------------------------------------------------------------


class TestFormatErrorsForPrompt:
    def test_empty_errors_returns_empty_string(self) -> None:
        result = PolicyValidator.format_errors_for_prompt([])
        assert result == ""

    def test_single_error_appears_in_output(self) -> None:
        result = PolicyValidator.format_errors_for_prompt(["rules is required"])
        assert "rules is required" in result

    def test_multiple_errors_all_appear(self) -> None:
        errors = ["err one", "err two", "err three"]
        result = PolicyValidator.format_errors_for_prompt(errors)
        for e in errors:
            assert e in result

    def test_output_starts_with_header(self) -> None:
        result = PolicyValidator.format_errors_for_prompt(["some error"])
        assert result.startswith("Fix these validation errors:")

    def test_errors_formatted_as_bullets(self) -> None:
        result = PolicyValidator.format_errors_for_prompt(["err one", "err two"])
        assert "  - err one" in result
        assert "  - err two" in result

    def test_returns_string(self) -> None:
        assert isinstance(PolicyValidator.format_errors_for_prompt(["x"]), str)
        assert isinstance(PolicyValidator.format_errors_for_prompt([]), str)


# ---------------------------------------------------------------------------
# _extract_errors() — internal, tested via validate()
# ---------------------------------------------------------------------------


class TestExtractErrors:
    def test_fallback_for_non_jsonschema_exception(self) -> None:
        """Non-jsonschema exceptions must still produce a non-empty list."""
        errors = PolicyValidator._extract_errors(ValueError("something broke"))
        assert len(errors) == 1
        assert "something broke" in errors[0]

    def test_jsonschema_validation_error_extracted(self) -> None:
        jsonschema = pytest.importorskip("jsonschema")
        schema = {"type": "object", "required": ["rules"]}
        try:
            jsonschema.validate({}, schema)
        except jsonschema.ValidationError as exc:
            errors = PolicyValidator._extract_errors(exc)
            assert len(errors) > 0
            assert all(isinstance(e, str) for e in errors)
