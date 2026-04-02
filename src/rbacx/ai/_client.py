"""Thin async transport wrapper over the OpenAI-compatible chat completions API."""

from typing import Any

from rbacx.ai.exceptions import PolicyGenerationError

try:
    from openai import AsyncOpenAI
except ImportError:  # pragma: no cover — only absent without rbacx[ai]
    AsyncOpenAI = None  # type: ignore[assignment,misc]


class LLMClient:
    """Thin transport wrapper over ``openai.AsyncOpenAI``.

    Single responsibility: send a list of chat messages and return the raw
    text content of the model response.  No policy logic, no retry logic
    beyond what the OpenAI SDK already provides internally.

    Supports any OpenAI-compatible provider by accepting a custom
    ``base_url`` — e.g. OpenRouter, Ollama, Azure OpenAI, etc.

    Args:
        api_key: provider API key.
        model: model identifier, e.g. ``"gpt-4o"``,
               ``"anthropic/claude-3-5-sonnet"`` (OpenRouter),
               ``"llama3"`` (Ollama).
        base_url: optional base URL override.  ``None`` uses the standard
                  OpenAI endpoint (``https://api.openai.com/v1``).
        timeout: HTTP request timeout in seconds passed to the SDK.
    """

    def __init__(
        self,
        api_key: str,
        model: str,
        base_url: str | None = None,
        timeout: float = 60.0,
    ) -> None:
        if AsyncOpenAI is None:  # pragma: no cover
            raise ImportError(
                "rbacx[ai] requires the 'openai' package. " "Install it with: pip install rbacx[ai]"
            )
        self._model = model
        kwargs: dict[str, Any] = {"api_key": api_key, "timeout": timeout}
        if base_url is not None:
            kwargs["base_url"] = base_url
        self._client = AsyncOpenAI(**kwargs)

    @property
    def model(self) -> str:
        """Model identifier used for completions."""
        return self._model

    async def complete(self, messages: list[dict[str, str]]) -> str:
        """Send *messages* to the LLM and return the raw text response.

        Args:
            messages: list of ``{"role": ..., "content": ...}`` dicts in
                      OpenAI chat format.

        Returns:
            Raw string content from the first choice of the model response.

        Raises:
            PolicyGenerationError: if the response content is ``None`` or
                                   empty (the model returned no usable text).
        """
        response = await self._client.chat.completions.create(
            model=self._model,
            messages=messages,  # type: ignore[arg-type]
        )
        content: str | None = response.choices[0].message.content
        if not content or not content.strip():
            raise PolicyGenerationError(
                "LLM returned an empty response. "
                "Try a different model or check your prompt configuration."
            )
        return content
