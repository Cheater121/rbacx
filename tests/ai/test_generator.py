"""Tests for rbacx.ai._generator.PolicyGenerator."""

import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from rbacx.ai._generator import PolicyGenerator
from rbacx.ai.exceptions import PolicyGenerationError, ValidationRetryError

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

_VALID_POLICY: dict[str, Any] = {
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

_VALID_RAW = json.dumps(_VALID_POLICY)

_INVALID_POLICY: dict[str, Any] = {
    "algorithm": "deny-overrides",
    # missing "rules" key -> fails validation
}

_INVALID_RAW = json.dumps(_INVALID_POLICY)

# Sentinel error list used when mocking a validation failure
_VALIDATION_ERRORS = ["rules: 'rules' is a required property"]


def _make_client(*responses: str) -> MagicMock:
    """Return a mock LLMClient whose complete() returns responses in order."""
    client = MagicMock()
    client.complete = AsyncMock(side_effect=list(responses))
    return client


def _make_generator(*responses: str) -> PolicyGenerator:
    return PolicyGenerator(_make_client(*responses))


def _messages() -> list[dict[str, str]]:
    return [{"role": "user", "content": "generate a policy"}]


def _fail_then_pass():
    """validate() fails on first call, passes on second."""
    return patch(
        "rbacx.ai._generator.PolicyValidator.validate",
        side_effect=[_VALIDATION_ERRORS, []],
    )


# ---------------------------------------------------------------------------
# _parse_json
# ---------------------------------------------------------------------------


class TestParseJson:
    def test_clean_json_object(self) -> None:
        result = PolicyGenerator._parse_json(_VALID_RAW)
        assert result == _VALID_POLICY

    def test_strips_json_fence(self) -> None:
        fenced = "```json\n" + _VALID_RAW + "\n```"
        result = PolicyGenerator._parse_json(fenced)
        assert result == _VALID_POLICY

    def test_strips_plain_fence(self) -> None:
        fenced = "```\n" + _VALID_RAW + "\n```"
        result = PolicyGenerator._parse_json(fenced)
        assert result == _VALID_POLICY

    def test_strips_surrounding_whitespace(self) -> None:
        result = PolicyGenerator._parse_json("  \n" + _VALID_RAW + "\n  ")
        assert result == _VALID_POLICY

    def test_fenced_with_trailing_whitespace(self) -> None:
        fenced = "```json\n" + _VALID_RAW + "\n```  "
        result = PolicyGenerator._parse_json(fenced)
        assert result == _VALID_POLICY

    def test_invalid_json_raises_policy_generation_error(self) -> None:
        with pytest.raises(PolicyGenerationError, match="not valid JSON"):
            PolicyGenerator._parse_json("{not json}")

    def test_json_array_raises_policy_generation_error(self) -> None:
        with pytest.raises(PolicyGenerationError, match="dict"):
            PolicyGenerator._parse_json("[1, 2, 3]")

    def test_json_string_raises_policy_generation_error(self) -> None:
        with pytest.raises(PolicyGenerationError):
            PolicyGenerator._parse_json('"just a string"')

    def test_json_null_raises_policy_generation_error(self) -> None:
        with pytest.raises(PolicyGenerationError):
            PolicyGenerator._parse_json("null")

    def test_policy_generation_error_has_cause_for_json_error(self) -> None:
        with pytest.raises(PolicyGenerationError) as exc_info:
            PolicyGenerator._parse_json("bad json")
        assert exc_info.value.cause is not None


# ---------------------------------------------------------------------------
# generate -- safe_mode=False
# ---------------------------------------------------------------------------


class TestGenerateSafeModeOff:
    @pytest.mark.asyncio
    async def test_returns_dict_and_raw(self) -> None:
        with patch("rbacx.ai._generator.PolicyValidator.validate", return_value=[]):
            gen = _make_generator(_VALID_RAW)
            policy, raw = await gen.generate(_messages(), safe_mode=False)
            assert policy == _VALID_POLICY
            assert raw == _VALID_RAW

    @pytest.mark.asyncio
    async def test_client_called_exactly_once(self) -> None:
        client = _make_client(_VALID_RAW)
        gen = PolicyGenerator(client)
        with patch("rbacx.ai._generator.PolicyValidator.validate", return_value=[]):
            await gen.generate(_messages(), safe_mode=False)
        assert client.complete.call_count == 1

    @pytest.mark.asyncio
    async def test_no_validation_even_for_invalid_policy(self) -> None:
        """safe_mode=False must skip validation entirely."""
        with patch("rbacx.ai._generator.PolicyValidator.validate", return_value=[]) as mv:
            gen = _make_generator(_INVALID_RAW)
            policy, raw = await gen.generate(_messages(), safe_mode=False)
            assert policy == _INVALID_POLICY
            mv.assert_not_called()

    @pytest.mark.asyncio
    async def test_invalid_json_still_raises(self) -> None:
        """JSON parse errors always propagate regardless of safe_mode."""
        gen = _make_generator("not json at all")
        with pytest.raises(PolicyGenerationError):
            await gen.generate(_messages(), safe_mode=False)


# ---------------------------------------------------------------------------
# generate -- safe_mode=True, first attempt succeeds
# ---------------------------------------------------------------------------


class TestGenerateSafeModeFirstSuccess:
    @pytest.mark.asyncio
    async def test_returns_valid_policy(self) -> None:
        with patch("rbacx.ai._generator.PolicyValidator.validate", return_value=[]):
            gen = _make_generator(_VALID_RAW)
            policy, raw = await gen.generate(_messages())
        assert policy == _VALID_POLICY

    @pytest.mark.asyncio
    async def test_returns_raw_string(self) -> None:
        with patch("rbacx.ai._generator.PolicyValidator.validate", return_value=[]):
            gen = _make_generator(_VALID_RAW)
            _, raw = await gen.generate(_messages())
        assert raw == _VALID_RAW

    @pytest.mark.asyncio
    async def test_client_called_once_on_success(self) -> None:
        client = _make_client(_VALID_RAW)
        gen = PolicyGenerator(client)
        with patch("rbacx.ai._generator.PolicyValidator.validate", return_value=[]):
            await gen.generate(_messages())
        assert client.complete.call_count == 1


# ---------------------------------------------------------------------------
# generate -- safe_mode=True, first fails, retry succeeds
# ---------------------------------------------------------------------------


class TestGenerateSafeModeRetrySuccess:
    @pytest.mark.asyncio
    async def test_client_called_twice_on_retry(self) -> None:
        client = _make_client(_INVALID_RAW, _VALID_RAW)
        gen = PolicyGenerator(client)
        with _fail_then_pass():
            await gen.generate(_messages())
        assert client.complete.call_count == 2

    @pytest.mark.asyncio
    async def test_returns_corrected_policy(self) -> None:
        with _fail_then_pass():
            gen = _make_generator(_INVALID_RAW, _VALID_RAW)
            policy, _ = await gen.generate(_messages())
        assert policy == _VALID_POLICY

    @pytest.mark.asyncio
    async def test_raw_is_from_second_attempt(self) -> None:
        with _fail_then_pass():
            gen = _make_generator(_INVALID_RAW, _VALID_RAW)
            _, raw = await gen.generate(_messages())
        assert raw == _VALID_RAW

    @pytest.mark.asyncio
    async def test_fix_messages_contain_validation_errors(self) -> None:
        """The second call to complete() must receive messages with error info."""
        client = _make_client(_INVALID_RAW, _VALID_RAW)
        gen = PolicyGenerator(client)
        with _fail_then_pass():
            await gen.generate(_messages())
        second_call_messages: list[dict[str, str]] = client.complete.call_args_list[1][0][0]
        combined = " ".join(m["content"] for m in second_call_messages)
        assert any(w in combined.lower() for w in ["fix", "error", "validation"])


# ---------------------------------------------------------------------------
# generate -- safe_mode=True, both attempts fail
# ---------------------------------------------------------------------------


class TestGenerateSafeModeRetryFail:
    @pytest.mark.asyncio
    async def test_raises_validation_retry_error(self) -> None:
        with patch("rbacx.ai._generator.PolicyValidator.validate", return_value=_VALIDATION_ERRORS):
            gen = _make_generator(_INVALID_RAW, _INVALID_RAW)
            with pytest.raises(ValidationRetryError):
                await gen.generate(_messages())

    @pytest.mark.asyncio
    async def test_client_called_exactly_twice(self) -> None:
        client = _make_client(_INVALID_RAW, _INVALID_RAW)
        gen = PolicyGenerator(client)
        with patch("rbacx.ai._generator.PolicyValidator.validate", return_value=_VALIDATION_ERRORS):
            with pytest.raises(ValidationRetryError):
                await gen.generate(_messages())
        assert client.complete.call_count == 2

    @pytest.mark.asyncio
    async def test_error_contains_raw_from_last_attempt(self) -> None:
        second_raw = json.dumps({"oops": True})
        client = _make_client(_INVALID_RAW, second_raw)
        gen = PolicyGenerator(client)
        with patch("rbacx.ai._generator.PolicyValidator.validate", return_value=_VALIDATION_ERRORS):
            with pytest.raises(ValidationRetryError) as exc_info:
                await gen.generate(_messages())
        assert exc_info.value.raw == second_raw

    @pytest.mark.asyncio
    async def test_error_contains_validation_errors_list(self) -> None:
        with patch("rbacx.ai._generator.PolicyValidator.validate", return_value=_VALIDATION_ERRORS):
            gen = _make_generator(_INVALID_RAW, _INVALID_RAW)
            with pytest.raises(ValidationRetryError) as exc_info:
                await gen.generate(_messages())
        assert exc_info.value.validation_errors == _VALIDATION_ERRORS

    @pytest.mark.asyncio
    async def test_first_attempt_json_error_raises_immediately(self) -> None:
        """JSON parse failure on first attempt -> PolicyGenerationError, no retry."""
        client = _make_client("not json", _VALID_RAW)
        gen = PolicyGenerator(client)
        with patch("rbacx.ai._generator.PolicyValidator.validate", return_value=[]):
            with pytest.raises(PolicyGenerationError):
                await gen.generate(_messages())
        assert client.complete.call_count == 1

    @pytest.mark.asyncio
    async def test_second_attempt_json_error_raises_policy_generation_error(self) -> None:
        """JSON parse failure on retry -> PolicyGenerationError (not ValidationRetryError)."""
        client = _make_client(_INVALID_RAW, "still not json")
        gen = PolicyGenerator(client)
        with patch("rbacx.ai._generator.PolicyValidator.validate", return_value=_VALIDATION_ERRORS):
            with pytest.raises(PolicyGenerationError):
                await gen.generate(_messages())
