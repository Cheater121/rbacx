"""Tests for rbacx.ai.exceptions."""

import pytest

from rbacx.ai.exceptions import (
    PolicyGenerationError,
    SchemaParseError,
    ValidationRetryError,
)


class TestSchemaParseError:
    def test_message_only(self) -> None:
        err = SchemaParseError("bad format")
        assert str(err) == "bad format"
        assert err.format_hint is None

    def test_with_format_hint(self) -> None:
        err = SchemaParseError("bad format", format_hint="openapi3")
        assert err.format_hint == "openapi3"

    def test_is_exception(self) -> None:
        assert isinstance(SchemaParseError("x"), Exception)

    def test_can_be_raised_and_caught(self) -> None:
        with pytest.raises(SchemaParseError) as exc_info:
            raise SchemaParseError("oops", format_hint="openapi2")
        assert exc_info.value.format_hint == "openapi2"


class TestValidationRetryError:
    def test_stores_raw_and_errors(self) -> None:
        err = ValidationRetryError(
            "both attempts failed",
            raw='{"bad": true}',
            validation_errors=["rules is required", "effect must be permit or deny"],
        )
        assert err.raw == '{"bad": true}'
        assert len(err.validation_errors) == 2
        assert "rules is required" in err.validation_errors

    def test_message(self) -> None:
        err = ValidationRetryError("msg", raw="r", validation_errors=[])
        assert str(err) == "msg"

    def test_empty_validation_errors(self) -> None:
        err = ValidationRetryError("msg", raw="r", validation_errors=[])
        assert err.validation_errors == []

    def test_is_exception(self) -> None:
        assert isinstance(ValidationRetryError("x", raw="", validation_errors=[]), Exception)

    def test_can_be_raised_and_caught(self) -> None:
        with pytest.raises(ValidationRetryError) as exc_info:
            raise ValidationRetryError("fail", raw="raw_output", validation_errors=["e1"])
        assert exc_info.value.raw == "raw_output"


class TestPolicyGenerationError:
    def test_message_only(self) -> None:
        err = PolicyGenerationError("something went wrong")
        assert str(err) == "something went wrong"
        assert err.cause is None

    def test_with_cause(self) -> None:
        original = ValueError("original")
        err = PolicyGenerationError("wrapped", cause=original)
        assert err.cause is original

    def test_cause_none_explicit(self) -> None:
        err = PolicyGenerationError("msg", cause=None)
        assert err.cause is None

    def test_is_exception(self) -> None:
        assert isinstance(PolicyGenerationError("x"), Exception)

    def test_can_be_raised_and_caught(self) -> None:
        with pytest.raises(PolicyGenerationError) as exc_info:
            raise PolicyGenerationError("bad json", cause=ValueError("parse error"))
        assert isinstance(exc_info.value.cause, ValueError)

    def test_all_three_are_distinct_types(self) -> None:
        assert SchemaParseError is not ValidationRetryError
        assert ValidationRetryError is not PolicyGenerationError
        assert SchemaParseError is not PolicyGenerationError
