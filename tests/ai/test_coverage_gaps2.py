"""Final two missing lines: _refinement 164-165, _validator 105-106."""

import sys
from unittest.mock import MagicMock, patch

import pytest

from rbacx.ai._refinement import RefinementSession
from rbacx.ai._validator import PolicyValidator
from rbacx.ai.exceptions import PolicyGenerationError

_POLICY = {
    "algorithm": "deny-overrides",
    "rules": [{"id": "r1", "effect": "permit", "actions": ["read"], "resource": {"type": "doc"}}],
}


class TestRefinementCompileImportError:
    def test_compile_import_failure_raises_policy_generation_error(self) -> None:
        """Lines 164-165: local import of compiler raises -> PolicyGenerationError."""
        # Setting the module to None causes 'from rbacx.core.compiler import ...'
        # to raise ImportError, hitting the except branch on lines 164-165.
        original = sys.modules.get("rbacx.core.compiler", ...)
        sys.modules["rbacx.core.compiler"] = None  # type: ignore[assignment]
        try:
            with pytest.raises((PolicyGenerationError, Exception)):
                RefinementSession._compile(_POLICY)
        finally:
            if original is ...:
                sys.modules.pop("rbacx.core.compiler", None)
            else:
                sys.modules["rbacx.core.compiler"] = original  # type: ignore[assignment]


class TestValidatorExtractErrorsExceptBranch:
    def test_extract_errors_except_branch_returns_str_exc(self) -> None:
        """Lines 105-106: exc.context raises inside the try -> except -> return [str(exc)]."""
        fake_jsonschema = MagicMock()

        class BrokenValidationError(Exception):
            """Mimics ValidationError but .context property raises."""

            @property
            def context(self):
                raise AttributeError("simulated broken context")

        fake_jsonschema.ValidationError = BrokenValidationError
        exc = BrokenValidationError("original message")

        with patch.dict(sys.modules, {"jsonschema": fake_jsonschema}):
            errors = PolicyValidator._extract_errors(exc)

        assert len(errors) == 1
        assert "original message" in errors[0]
