"""Typed exceptions for the rbacx AI Policy Authoring System."""


class SchemaParseError(Exception):
    """Raised when the input schema format cannot be recognised or parsed.

    Attributes:
        format_hint: detected or expected format string for diagnostics
                     (e.g. ``"openapi3"``, ``"openapi2"``).  May be ``None``
                     when the format is completely unrecognised.
    """

    def __init__(self, message: str, format_hint: str | None = None) -> None:
        super().__init__(message)
        self.format_hint: str | None = format_hint


class ValidationRetryError(Exception):
    """Raised when both validation attempts fail in the ``safe_mode`` pipeline.

    The generator tried to fix the policy once after the initial validation
    failure; this exception means the second attempt also produced an invalid
    policy.

    Attributes:
        raw: raw LLM output from the *last* generation attempt.
        validation_errors: list of human-readable jsonschema error messages
                           collected from the final failed validation.
    """

    def __init__(
        self,
        message: str,
        raw: str,
        validation_errors: list[str],
    ) -> None:
        super().__init__(message)
        self.raw: str = raw
        self.validation_errors: list[str] = validation_errors


class PolicyGenerationError(Exception):
    """Raised for general generation failures.

    Examples of situations that trigger this exception:

    * The LLM response is not parseable JSON.
    * The LLM returned an empty response.
    * ``compile=True`` was requested but the rbacx compiler is unavailable.
    * ``input_attrs`` passed to ``explain_decision`` is missing required fields.

    Attributes:
        cause: the original exception that triggered this error, if available.
    """

    def __init__(self, message: str, cause: Exception | None = None) -> None:
        super().__init__(message)
        self.cause: Exception | None = cause
