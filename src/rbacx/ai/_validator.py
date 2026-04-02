"""Thin adapter over rbacx DSL validation and linting utilities."""

from typing import Any

from rbacx.dsl.lint import Issue, analyze_policy
from rbacx.dsl.validate import validate_policy


class PolicyValidator:
    """Deterministic policy validator — no LLM interaction.

    Wraps :func:`rbacx.dsl.validate.validate_policy` (JSON Schema structural
    check) and :func:`rbacx.dsl.lint.analyze_policy` (semantic analysis) with
    a prompt-friendly error-formatting layer used by the generation pipeline.

    All methods are static; no instance state is required.
    """

    @staticmethod
    def validate(policy: dict[str, Any]) -> list[str]:
        """Run JSON Schema validation against the rbacx policy schema.

        Args:
            policy: policy dict to validate.

        Returns:
            Empty list when the policy is structurally valid.
            Non-empty list of human-readable error strings on failure.
            Each string follows the pattern ``"<json_path>: <message>"``.
        """
        try:
            validate_policy(policy)
            return []
        except Exception as exc:
            return PolicyValidator._extract_errors(exc)

    @staticmethod
    def lint(policy: dict[str, Any]) -> list[Issue]:
        """Run semantic analysis via :func:`analyze_policy`.

        Args:
            policy: structurally valid policy dict.

        Returns:
            List of :class:`~rbacx.dsl.lint.Issue` dicts (may be empty).
            Each issue has at minimum a ``"code"`` key.
        """
        return analyze_policy(policy)

    @staticmethod
    def format_errors_for_prompt(errors: list[str]) -> str:
        """Format validation error strings into a concise repair instruction.

        Used to build the fix-prompt when the first generation attempt fails
        validation.

        Args:
            errors: list returned by :meth:`validate`.

        Returns:
            Empty string when *errors* is empty, otherwise a multi-line string
            starting with ``"Fix these validation errors:"`` followed by a
            bullet list of error messages.

        Example::

            Fix these validation errors:
              - rules[0].effect: 'permitt' is not one of ['permit', 'deny']
              - rules[1].actions: [] is too short
        """
        if not errors:
            return ""
        lines = ["Fix these validation errors:"]
        lines.extend(f"  - {e}" for e in errors)
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_errors(exc: Exception) -> list[str]:
        """Extract readable error strings from a jsonschema ValidationError.

        Falls back to ``str(exc)`` for non-jsonschema exceptions so that the
        method always returns a non-empty list when called from a failure path.
        """
        # jsonschema raises ValidationError; it may also raise SchemaError.
        # We handle both by looking for the standard attributes.
        try:
            # jsonschema.ValidationError has `.context` for sub-errors and
            # `.message` + `.json_path` / `.absolute_path` for the root error.
            import jsonschema  # type: ignore[import-untyped]

            if isinstance(exc, jsonschema.ValidationError):
                # Collect all leaf errors from the context tree when present.
                sub = list(exc.context)
                if sub:
                    return [
                        f"{'.'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.message}"
                        for e in sub
                    ]
                path = ".".join(str(p) for p in exc.absolute_path) or "<root>"
                return [f"{path}: {exc.message}"]
        except Exception:
            pass
        return [str(exc)]
