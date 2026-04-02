"""PolicyGenerator: orchestrates the safe_mode generation pipeline."""

import json
from typing import Any

from rbacx.ai._client import LLMClient
from rbacx.ai._prompt import PromptBuilder
from rbacx.ai._validator import PolicyValidator
from rbacx.ai.exceptions import PolicyGenerationError, ValidationRetryError


class PolicyGenerator:
    """Orchestrates LLM calls and the ``safe_mode`` validation pipeline.

    Responsibilities:

    * Call :class:`~rbacx.ai._client.LLMClient` with the provided messages.
    * Parse the raw LLM response into a ``dict``.
    * When ``safe_mode=True``: validate the result and retry once with a
      fix-prompt if validation fails; raise :exc:`ValidationRetryError` if
      the second attempt also fails.
    * Return ``(policy_dict, raw_llm_output)`` on success.

    Args:
        client: configured :class:`~rbacx.ai._client.LLMClient` instance.
    """

    def __init__(self, client: LLMClient) -> None:
        self._client = client
        self._validator = PolicyValidator()

    async def generate(
        self,
        messages: list[dict[str, str]],
        *,
        safe_mode: bool = True,
    ) -> tuple[dict[str, Any], str]:
        """Generate a policy dict from *messages*.

        Pipeline when ``safe_mode=True``:

        1. ``LLMClient.complete(messages)`` → *raw*
        2. :meth:`_parse_json` (*raw*) → *dict*
        3. :meth:`PolicyValidator.validate` (*dict*)

           * Success → return ``(dict, raw)``
           * Failure → build fix-messages → repeat step 1-3 once more

             * Success → return ``(dict, raw)``
             * Failure → raise :exc:`ValidationRetryError`

        Pipeline when ``safe_mode=False``:

        1. ``LLMClient.complete(messages)`` → *raw*
        2. :meth:`_parse_json` (*raw*) → *dict*
        3. return ``(dict, raw)`` immediately, no validation

        Args:
            messages: complete chat-messages list for the LLM.
            safe_mode: whether to run validate → retry → lint pipeline.

        Returns:
            ``(policy_dict, raw_llm_output)`` tuple.

        Raises:
            PolicyGenerationError: LLM response is not parseable JSON or
                                   not a dict.
            ValidationRetryError: ``safe_mode=True`` and both validation
                                   attempts fail.
        """
        raw = await self._client.complete(messages)
        policy = self._parse_json(raw)

        if not safe_mode:
            return policy, raw

        errors = self._validator.validate(policy)
        if not errors:
            return policy, raw

        # First attempt failed — build fix prompt and retry once
        fix_messages = PromptBuilder.build_fix(messages, raw, errors)
        raw = await self._client.complete(fix_messages)
        policy = self._parse_json(raw)

        errors = self._validator.validate(policy)
        if not errors:
            return policy, raw

        raise ValidationRetryError(
            "Policy validation failed after two attempts. "
            "The generated policy does not conform to the rbacx DSL schema. "
            "Check the raw output and validation errors for details.",
            raw=raw,
            validation_errors=errors,
        )

    @staticmethod
    def _parse_json(raw: str) -> dict[str, Any]:
        """Parse *raw* LLM output into a policy dict.

        Strips Markdown code fences (`` ```json ... ``` `` or `` ``` ... ``` ``)
        and surrounding whitespace before attempting JSON parsing.

        Args:
            raw: raw string returned by the LLM.

        Returns:
            Parsed policy dict.

        Raises:
            PolicyGenerationError: if the text is not valid JSON or the
                                   top-level value is not a ``dict``.
        """
        text = raw.strip()

        # Strip markdown fences: ```json\n...\n``` or ```\n...\n```
        if text.startswith("```"):
            # Remove opening fence (with optional language tag)
            first_newline = text.find("\n")
            if first_newline != -1:
                text = text[first_newline + 1 :]
            # Remove closing fence
            if text.rstrip().endswith("```"):
                text = text.rstrip()[:-3].rstrip()

        text = text.strip()

        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise PolicyGenerationError(
                f"LLM response is not valid JSON: {exc}. "
                "Ensure the model follows the output format instructions.",
                cause=exc,
            ) from exc

        if not isinstance(data, dict):
            raise PolicyGenerationError(
                f"Expected a JSON object (dict) from the LLM, "
                f"got {type(data).__name__}. "
                "Ensure the model returns a policy object, not an array or scalar.",
            )

        return data
