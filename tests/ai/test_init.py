"""Smoke tests for rbacx.ai public API surface."""

from rbacx.ai import (
    AIPolicy,
    DecisionExplanation,
    PolicyGenerationError,
    PolicyResult,
    SchemaParseError,
    ValidationRetryError,
)
from rbacx.ai import __all__ as public_api

# ---------------------------------------------------------------------------
# Public names
# ---------------------------------------------------------------------------


class TestPublicApi:
    _EXPECTED = {
        "AIPolicy",
        "PolicyResult",
        "DecisionExplanation",
        "SchemaParseError",
        "ValidationRetryError",
        "PolicyGenerationError",
    }

    def test_all_expected_names_importable(self) -> None:
        for name in self._EXPECTED:
            assert name in public_api, f"{name!r} missing from __all__"

    def test_no_unexpected_names_in_all(self) -> None:
        extras = set(public_api) - self._EXPECTED
        assert not extras, f"Unexpected names in __all__: {extras}"

    def test_ai_policy_is_class(self) -> None:
        assert isinstance(AIPolicy, type)

    def test_policy_result_is_class(self) -> None:
        assert isinstance(PolicyResult, type)

    def test_decision_explanation_is_class(self) -> None:
        assert isinstance(DecisionExplanation, type)

    def test_schema_parse_error_is_exception(self) -> None:
        assert issubclass(SchemaParseError, Exception)

    def test_validation_retry_error_is_exception(self) -> None:
        assert issubclass(ValidationRetryError, Exception)

    def test_policy_generation_error_is_exception(self) -> None:
        assert issubclass(PolicyGenerationError, Exception)

    def test_all_six_names_imported_without_error(self) -> None:
        # If we reached this point the top-level imports succeeded
        assert AIPolicy is not None
        assert PolicyResult is not None
        assert DecisionExplanation is not None
        assert SchemaParseError is not None
        assert ValidationRetryError is not None
        assert PolicyGenerationError is not None


# ---------------------------------------------------------------------------
# Module-level docstring
# ---------------------------------------------------------------------------


class TestModuleDocstring:
    def test_module_has_docstring(self) -> None:
        import rbacx.ai as module

        assert module.__doc__ is not None
        assert len(module.__doc__.strip()) > 0

    def test_docstring_mentions_ai_policy(self) -> None:
        import rbacx.ai as module

        assert "AIPolicy" in module.__doc__

    def test_docstring_mentions_install(self) -> None:
        import rbacx.ai as module

        assert "pip install" in module.__doc__
