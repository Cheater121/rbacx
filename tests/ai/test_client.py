"""Tests for rbacx.ai._client.LLMClient."""

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from rbacx.ai._client import LLMClient
from rbacx.ai.exceptions import PolicyGenerationError


def _make_response(content: str | None) -> MagicMock:
    """Build a mock openai ChatCompletion response."""
    message = MagicMock()
    message.content = content
    choice = MagicMock()
    choice.message = message
    response = MagicMock()
    response.choices = [choice]
    return response


def _make_client(
    content: str | None = '{"rules": []}',
    *,
    api_key: str = "sk-test",
    model: str = "gpt-4o",
    base_url: str | None = None,
) -> tuple[LLMClient, MagicMock]:
    """Return (LLMClient, mock_async_openai_instance)."""
    mock_create = AsyncMock(return_value=_make_response(content))
    mock_openai = MagicMock()
    mock_openai.chat.completions.create = mock_create

    with patch("rbacx.ai._client.AsyncOpenAI", return_value=mock_openai):
        client = LLMClient(api_key=api_key, model=model, base_url=base_url)
    return client, mock_openai


class TestLLMClientInit:
    def test_model_property(self) -> None:
        client, _ = _make_client(model="gpt-4o-mini")
        assert client.model == "gpt-4o-mini"

    def test_base_url_none_not_passed_to_sdk(self) -> None:
        """When base_url is None, AsyncOpenAI must NOT receive a base_url kwarg."""
        with patch("rbacx.ai._client.AsyncOpenAI") as mock_cls:
            mock_cls.return_value = MagicMock()
            LLMClient(api_key="sk-test", model="gpt-4o", base_url=None)
            _, kwargs = mock_cls.call_args
            assert "base_url" not in kwargs

    def test_base_url_passed_when_provided(self) -> None:
        """When base_url is given, AsyncOpenAI must receive it."""
        url = "https://openrouter.ai/api/v1"
        with patch("rbacx.ai._client.AsyncOpenAI") as mock_cls:
            mock_cls.return_value = MagicMock()
            LLMClient(api_key="sk-test", model="gpt-4o", base_url=url)
            _, kwargs = mock_cls.call_args
            assert kwargs.get("base_url") == url

    def test_api_key_forwarded(self) -> None:
        with patch("rbacx.ai._client.AsyncOpenAI") as mock_cls:
            mock_cls.return_value = MagicMock()
            LLMClient(api_key="sk-secret", model="gpt-4o")
            _, kwargs = mock_cls.call_args
            assert kwargs.get("api_key") == "sk-secret"

    def test_timeout_forwarded(self) -> None:
        with patch("rbacx.ai._client.AsyncOpenAI") as mock_cls:
            mock_cls.return_value = MagicMock()
            LLMClient(api_key="sk-test", model="gpt-4o", timeout=30.0)
            _, kwargs = mock_cls.call_args
            assert kwargs.get("timeout") == 30.0

    def test_default_timeout(self) -> None:
        with patch("rbacx.ai._client.AsyncOpenAI") as mock_cls:
            mock_cls.return_value = MagicMock()
            LLMClient(api_key="sk-test", model="gpt-4o")
            _, kwargs = mock_cls.call_args
            assert kwargs.get("timeout") == 60.0


class TestLLMClientComplete:
    @pytest.mark.asyncio
    async def test_returns_content_string(self) -> None:
        client, mock_openai = _make_client(content='{"rules": []}')
        result = await client.complete([{"role": "user", "content": "generate"}])
        assert result == '{"rules": []}'

    @pytest.mark.asyncio
    async def test_passes_messages_to_sdk(self) -> None:
        client, mock_openai = _make_client(content="ok")
        messages = [
            {"role": "system", "content": "you are helpful"},
            {"role": "user", "content": "make a policy"},
        ]
        await client.complete(messages)
        mock_openai.chat.completions.create.assert_called_once()
        call_kwargs: dict[str, Any] = mock_openai.chat.completions.create.call_args.kwargs
        assert call_kwargs["messages"] == messages

    @pytest.mark.asyncio
    async def test_passes_model_to_sdk(self) -> None:
        client, mock_openai = _make_client(content="ok", model="gpt-4o-mini")
        await client.complete([{"role": "user", "content": "hi"}])
        create_kwargs: dict[str, Any] = mock_openai.chat.completions.create.call_args.kwargs
        assert create_kwargs["model"] == "gpt-4o-mini"

    @pytest.mark.asyncio
    async def test_empty_content_raises(self) -> None:
        client, _ = _make_client(content="")
        with pytest.raises(PolicyGenerationError, match="empty response"):
            await client.complete([{"role": "user", "content": "hi"}])

    @pytest.mark.asyncio
    async def test_none_content_raises(self) -> None:
        client, _ = _make_client(content=None)
        with pytest.raises(PolicyGenerationError, match="empty response"):
            await client.complete([{"role": "user", "content": "hi"}])

    @pytest.mark.asyncio
    async def test_sdk_exception_propagates(self) -> None:
        """Exceptions from the SDK should propagate unchanged."""
        mock_openai = MagicMock()
        mock_openai.chat.completions.create = AsyncMock(side_effect=RuntimeError("network error"))
        with patch("rbacx.ai._client.AsyncOpenAI", return_value=mock_openai):
            client = LLMClient(api_key="sk-test", model="gpt-4o")
        with pytest.raises(RuntimeError, match="network error"):
            await client.complete([{"role": "user", "content": "hi"}])

    @pytest.mark.asyncio
    async def test_whitespace_only_content_raises(self) -> None:
        client, _ = _make_client(content="   ")
        with pytest.raises(PolicyGenerationError, match="empty response"):
            await client.complete([{"role": "user", "content": "hi"}])
